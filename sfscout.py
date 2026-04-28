# Copyright 2025 Google LLC
# Modifications Copyright 2026 Brain Kok

import requests
import re
import json
import logging
import platform
import traceback
import sys
import argparse
import os
from dataclasses import dataclass, field
from collections import deque
from itertools import islice
from datetime import datetime
from typing import Optional, Any, Iterator, List, Dict
from urllib.parse import urlparse, parse_qs
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from http.cookies import SimpleCookie

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TOOL_VERSION  = '1.0.0'
BROWSER_UA    = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/210100101 Firefox/85.0'
AURA_PATHS    = ['/s/sfsites/aura', '/s/aura', '/aura', '/sfsites/aura']

logger = logging.getLogger('sfscout')

# ─── Logging ──────────────────────────────────────────────────────────────────

class AnsiColourHandler(logging.StreamHandler):
    RESET  = '\x1b[0m'
    RED    = '\x1b[31m'
    YELLOW = '\x1b[33m'
    CYAN   = '\x1b[36m'

    LEVEL_COLOURS = {}

    @classmethod
    def _colour_for(cls, level):
        if level >= logging.CRITICAL: return cls.RED
        if level >= logging.ERROR:    return cls.RED
        if level >= logging.WARNING:  return cls.YELLOW
        if level >= logging.DEBUG:    return cls.CYAN
        return cls.RESET

    def format(self, record):
        return self._colour_for(record.levelno) + super().format(record) + self.RESET


class WindowsColourHandler(logging.StreamHandler):
    FG_RED    = 0x0004
    FG_YELLOW = 0x0006
    FG_CYAN   = 0x0003
    FG_WHITE  = 0x0007
    FG_BRIGHT = 0x0008
    BG_YELLOW = 0x0060
    BG_BRIGHT = 0x0080

    @classmethod
    def _colour_for(cls, level):
        if level >= logging.CRITICAL: return cls.BG_YELLOW | cls.BG_BRIGHT | cls.FG_RED | cls.FG_BRIGHT
        if level >= logging.ERROR:    return cls.FG_RED | cls.FG_BRIGHT
        if level >= logging.WARNING:  return cls.FG_YELLOW | cls.FG_BRIGHT
        if level >= logging.DEBUG:    return cls.FG_CYAN
        return cls.FG_WHITE

    def __init__(self, stream=None):
        super().__init__(stream)
        import ctypes, ctypes.util
        lib = ctypes.cdll.LoadLibrary(ctypes.util.find_msvcrt() or ctypes.util.find_library('msvcrt'))
        self._handle = lib._get_osfhandle(self.stream.fileno())

    def _set_colour(self, code):
        import ctypes
        ctypes.windll.kernel32.SetConsoleTextAttribute(self._handle, code)

    def emit(self, record):
        self._set_colour(self._colour_for(record.levelno))
        super().emit(record)
        self._set_colour(self.FG_WHITE)


def add_logging_level(name, num, method=None):
    method = method or name.lower()

    def _root(msg, *a, **kw):   logging.log(num, msg, *a, **kw)
    def _inst(self, msg, *a, **kw):
        if self.isEnabledFor(num): self._log(num, msg, a, **kw)

    logging.addLevelName(num, name)
    setattr(logging, name, num)
    setattr(logging.getLoggerClass(), method, _inst)
    setattr(logging, method, _root)


def init_logger(level):
    global logger
    Handler = WindowsColourHandler if platform.system() == 'Windows' else AnsiColourHandler
    logger  = logging.getLogger('sfscout')
    logger.setLevel(level)
    h = Handler()
    h.setLevel(level)
    logger.addHandler(h)


# ─── Data types ───────────────────────────────────────────────────────────────

@dataclass
class AuraResult:
    action_id : str
    ok        : bool
    payload   : Optional[Any]  = None
    error     : Optional[str]  = None
    raw       : Optional[dict] = None   # full action dict (needed for edge-case fields)


def _chunks(seq, size):
    it = iter(seq)
    while batch := list(islice(it, size)):
        yield batch


def _extract_records(rv) -> list:
    """Pull a records list out of an Aura payload regardless of nesting."""
    if not isinstance(rv, dict):
        return []
    for key in ('records', 'rows', 'data', 'items', 'result', 'list', 'recordList'):
        val = rv.get(key)
        if isinstance(val, list) and val:
            return val
        if isinstance(val, dict):
            for inner in ('records', 'rows', 'data', 'items'):
                inner_val = val.get(inner)
                if isinstance(inner_val, list) and inner_val:
                    return inner_val
    for val in rv.values():
        if isinstance(val, list) and val and isinstance(val[0], dict):
            return val
    return []


# ─── Core HTTP layer ──────────────────────────────────────────────────────────

class AuraProbe:
    """
    Handles low-level Salesforce Aura communication and exposes scanning methods
    for misconfiguration discovery on Experience Cloud instances.
    """

    _LIST_PROVIDER   = ('serviceComponent://ui.force.components.controllers.lists'
                        '.selectableListDataProvider.SelectableListDataProviderController'
                        '/ACTION$getItems')
    _LIST_PICKER     = ('serviceComponent://ui.force.components.controllers.lists'
                        '.listViewPickerDataProvider.ListViewPickerDataProviderController'
                        '/ACTION$getInitialListViews')
    _LIST_MANAGER    = ('serviceComponent://ui.force.components.controllers.lists'
                        '.listViewDataManager.ListViewDataManagerController/ACTION$getItems')
    _GRAPHQL_ACTION  = 'aura://RecordUiController/ACTION$executeGraphQL'
    _OBJECT_INFO     = 'aura://RecordUiController/ACTION$getObjectInfo'
    _HOST_CONFIG     = 'aura://HostConfigController/ACTION$getConfigData'
    _BOOTSTRAP       = ('serviceComponent://ui.communities.components.aura.components'
                        '.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData')
    _SELF_REG_CHECK  = 'apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled'
    _SELF_REG_URL    = 'apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl'

    def __init__(self, url, cookies, proxy, insecure, app, aura, context, token):
        self.base      = url.rstrip('/')
        self.headers   = {'User-Agent': BROWSER_UA, 'Accept': 'application/json'}
        self.session   = requests.Session()
        self.csp_sites : list = []
        self.gql_ok    : bool = False

        if cookies:
            for k, v in SimpleCookie(cookies).items():
                self.session.cookies.set(k, v)
            if not self.session.cookies.get('sid'):
                logger.error('SID missing from cookies — unauthenticated mode only')
        else:
            logger.error('No cookies — unauthenticated mode only')

        self.session.verify  = not insecure
        self.session.proxies = {} if not proxy else {'http': proxy, 'https': proxy}

        self.endpoint = self._locate_endpoint() if not aura  else aura
        logger.info(f'Endpoint: {self.base}{self.endpoint}')

        self.app_url  = self._detect_app()     if not app    else f'{self.base}/{app.lstrip("/")}'
        logger.info(f'App: {self.app_url}')

        self.ctx      = self._load_context()   if not context else context
        logger.debug(f'Context: {self.ctx}')

        self.token    = self._load_token()     if not token   else token
        logger.debug(f'Token: {self.token}')

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _action(aid, descriptor, params=None):
        return {'id': aid, 'descriptor': descriptor,
                'callingDescriptor': 'UNKNOWN', 'params': params or {}}

    @staticmethod
    def _context(fwuid, app, loaded):
        return json.dumps({'mode': 'PROD', 'fwuid': fwuid, 'app': app,
                           'loaded': loaded, 'dn': [], 'globals': {}, 'uad': False})

    @staticmethod
    def _stub_action():
        return AuraProbe._action(
            '242;a',
            'serviceComponent://ui.force.components.controllers.relatedList'
            '.RelatedListContainerDataProviderController/ACTION$getRecords',
            {'recordId': 'Foobar'}
        )

    @staticmethod
    def _stub_context():
        return AuraProbe._context(
            'INVALID', 'siteforce:loginApp2',
            {'APPLICATION@markup://siteforce:loginApp2': 'siteforce:loginApp2'}
        )

    def _envelope(self, actions, stub=False):
        return {
            'message':      json.dumps({'actions': [self._stub_action()]}) if stub
                            else json.dumps({'actions': actions}),
            'aura.context': self._stub_context() if stub else self.ctx,
            'aura.pageURI': 'unknown',
            'aura.token':   'undefined' if stub else self.token,
        }

    @staticmethod
    def _parse(resp) -> List[AuraResult]:
        try:
            data = resp.json()
        except Exception:
            logger.verbose(f'Non-JSON: {resp.text[:200]}')
            return []
        out = []
        for act in data.get('actions', []):
            aid, state = act.get('id'), act.get('state')
            if state == 'SUCCESS':
                out.append(AuraResult(aid, True, payload=act.get('returnValue'), raw=act))
            elif state == 'ERROR':
                err = (act.get('error') or [{}])[0]
                if 'event' in err:
                    vals = err['event']['attributes']['values']
                    msg  = (vals.get('error') or {}).get('message') or vals.get('message')
                else:
                    msg = err.get('message')
                out.append(AuraResult(aid, False, error=msg, raw=act))
        return out

    def _call(self, actions, chunk_size=100) -> List[AuraResult]:
        actions    = actions if isinstance(actions, list) else [actions]
        chunk_size = min(chunk_size, 100)
        results    : List[AuraResult] = []

        for idx, batch in enumerate(_chunks(actions, chunk_size)):
            if len(batch) > 1:
                logger.verbose(f'Batch #{idx}: {len(batch)} actions')
            try:
                resp = self.session.post(
                    f'{self.base}{self.endpoint}',
                    headers=self.headers,
                    data=self._envelope(batch),
                    timeout=90
                )
                results.extend(self._parse(resp))
            except requests.exceptions.SSLError:
                logger.error('SSL error — try -k to skip verification')
            except requests.exceptions.ReadTimeout:
                if chunk_size > 1:
                    logger.error('Timeout on batch, falling back to single requests…')
                    results.extend(self._call(batch, chunk_size=1))

        return results

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _locate_endpoint(self):
        stub = self._envelope([], stub=True)
        for path in AURA_PATHS:
            try:
                r = self.session.post(f'{self.base}{path}', allow_redirects=False,
                                      headers=self.headers, data=stub)
                if 'markup://' in r.text:
                    return path
                if r.status_code == 301 and r.headers.get('Location'):
                    loc = r.headers['Location']
                    r2  = self.session.post(loc, allow_redirects=False,
                                            headers=self.headers, data=stub)
                    if 'markup://' in r2.text:
                        return urlparse(loc).path
            except requests.exceptions.SSLError:
                logger.error('SSL error probing endpoints — try -k')
            except requests.exceptions.ConnectionError:
                logger.error('Cannot reach target, aborting')
                sys.exit(1)
            except Exception:
                logger.debug(traceback.format_exc())
        logger.critical('No Aura endpoint found')
        sys.exit(1)

    def _detect_app(self):
        for path in AURA_PATHS:
            if path in self.endpoint:
                return f'{self.base}{self.endpoint.replace(path, "")}/s'
        logger.error('Could not resolve app path, defaulting to /s')
        return f'{self.base}/s'

    def _load_context(self):
        resp = self.session.get(self.app_url, allow_redirects=True, headers=self.headers)
        text = resp.text

        redir_marker = f"window.location.href ='{self.base}"
        if redir_marker in text:
            m = re.search(r"window\.location\.href\s*=\s*'([^']+)", text)
            if m:
                try:
                    resp = self.session.get(m.group(1), allow_redirects=True, headers=self.headers)
                    text = resp.text
                except Exception:
                    logger.error('Failed to follow redirect while loading context')
                    raise

        fwuid  = re.search(r'"fwuid":"([^"]+)', text)
        markup = re.search(r'"(APPLICATION@markup[^"]+)":"([^"]+)"', text)
        app_m  = re.search(r'"app":"([^"]+)', text)

        if fwuid and markup and app_m:
            return self._context(fwuid.group(1), app_m.group(1),
                                 {markup.group(1): markup.group(2)})

        stub  = self._envelope([], stub=True)
        retry = self.session.post(f'{self.base}{self.endpoint}', data=stub,
                                  allow_redirects=True, headers=self.headers)
        raw   = retry.text

        if 'markup://aura:invalidSession' in raw:
            logger.critical('Invalid session — guest access may be disabled')
            sys.exit(1)

        fwuid_val = None
        m = re.search(r'Expected:(.*?) Actual', raw)
        if m:
            fwuid_val = m.group(1).strip()
        else:
            try:
                parsed    = json.loads(raw)
                fwuid_val = parsed.get('context', {}).get('fwuid')
            except Exception:
                pass

        if not fwuid_val:
            logger.critical('Unable to determine fwuid from any source')
            sys.exit(1)

        app_id = 'siteforce:loginApp2'
        return self._context(fwuid_val, app_id, {f'APPLICATION@markup://{app_id}': app_id})

    def _load_token(self):
        resp    = self.session.get(self.app_url, allow_redirects=True, headers=self.headers)
        pattern = r'eyJub[^";]+'
        for source in (resp.text, resp.headers.get('set-cookie', '')):
            m = re.search(pattern, source)
            if m:
                logger.verbose(f'Token found: {m.group(0)[:20]}…')
                return m.group(0)
        logger.error('Token not found, using null')
        return 'null'

    # ── Scanning ──────────────────────────────────────────────────────────────

    def fetch_objects(self) -> list:
        logger.verbose('Fetching object list and CSP trusted sites')
        rs = self._call(self._action('1;a', self._HOST_CONFIG))
        if not rs or not rs[0].ok:
            logger.error('Could not retrieve objects')
            return []
        self.csp_sites = rs[0].payload.get('cspTrustedSites', [])
        objects = list(rs[0].payload.get('apiNamesToKeyPrefixes', {}).keys())
        logger.info(f'Found {len(objects)} objects')
        return objects

    def check_permissions(self, objects) -> dict:
        logger.verbose('Checking CRUD permissions')
        actions = [self._action(obj, self._OBJECT_INFO, {'objectApiName': obj})
                   for obj in objects]
        results = {}
        for r in self._call(actions):
            if r.ok:
                rv = r.payload
                results[r.action_id] = {
                    'createable': rv.get('createable', False),
                    'updateable': rv.get('updateable', False),
                    'deletable':  rv.get('deletable',  False),
                }
            else:
                logger.debug(f'Permission unavailable — {r.action_id}: {r.error}')

        deletable  = [k for k, v in results.items() if v['deletable']]
        createable = [k for k, v in results.items() if v['createable']]
        updateable = [k for k, v in results.items() if v['updateable']]

        if deletable:  logger.warning(f'[CRITICAL] {len(deletable)} DELETABLE: {", ".join(deletable)}')
        if createable: logger.warning(f'[HIGH] {len(createable)} CREATEABLE: {", ".join(createable)}')
        if updateable: logger.warning(f'[HIGH] {len(updateable)} UPDATEABLE: {", ".join(updateable)}')
        if not any([deletable, createable, updateable]):
            logger.info('No write/delete permissions found on queried objects')

        return results

    def _iter_records(self, obj, page_size=200) -> Iterator:
        """Generator — yields (records_list, raw_payload) per page for one object."""
        page = 1
        while True:
            rs = self._call(self._action(obj, self._LIST_PROVIDER, {
                'entityNameOrId': obj, 'layoutType': 'FULL',
                'pageSize': page_size, 'currentPage': page,
                'useTimeout': False, 'getCount': False, 'enableRowActions': False,
            }))
            if not rs or not rs[0].ok:
                return
            rv      = rs[0].payload
            records = _extract_records(rv)
            if not records:
                logger.info(f'{obj}: payload returned no records — keys: '
                            f'{list(rv.keys()) if isinstance(rv, dict) else type(rv)}')
            yield records, rv          # always yield so caller receives rv even on empty
            if not records or len(records) < page_size:
                break
            page += 1

    def collect_records(self, objects, page_size=200) -> dict:
        results: dict = {}

        count_actions = [
            self._action(obj, self._LIST_PROVIDER, {
                'entityNameOrId': obj, 'layoutType': 'COMPACT',
                'pageSize': 1, 'currentPage': 1,
                'useTimeout': False, 'getCount': True, 'enableRowActions': False,
            })
            for obj in objects
        ]
        logger.info(f'Counting records for {len(objects)} objects')
        for r in self._call(count_actions):
            if r.ok:
                results[r.action_id] = {
                    'records':     [],
                    'total_count': r.payload.get('totalCount') or 0,
                    '_raw':        None,
                }
            else:
                logger.debug(f'Count failed — {r.action_id}: {r.error}')

        targets = [obj for obj, v in results.items() if v['total_count'] > 0]
        logger.info(f'{len(targets)} objects have accessible records, fetching…')

        for obj in targets:
            collected, raw_last = [], None
            for page_records, rv in self._iter_records(obj, page_size):
                raw_last = rv                   # always capture rv, even if records is empty
                if page_records:
                    collected.extend(page_records)
                if not page_records or len(collected) >= results[obj]['total_count']:
                    break
            results[obj]['records'] = collected
            results[obj]['_raw']    = raw_last
            if collected:
                logger.debug(f'Sample record structure for {obj}:\n'
                             + json.dumps(collected[0], indent=2)[:600])

        return results

    def fetch_ui_lists(self, objects) -> list:
        pick_actions = [
            self._action(obj, self._LIST_PICKER,
                         {'scope': obj, 'maxMruResults': 10, 'maxAllResults': 20})
            for obj in objects
        ]
        logger.verbose(f'Fetching UI list views for {len(objects)} objects')

        views_by_obj: dict = {}
        for r in self._call(pick_actions):
            if r.ok and r.payload.get('listViews'):
                views_by_obj[r.action_id] = r.payload['listViews']
            elif not r.ok:
                logger.debug(f'List view fetch failed — {r.action_id}: {r.error}')

        if not views_by_obj:
            logger.info('No UI record lists found')
            return []

        logger.info('Checking view accessibility')
        item_actions = []
        for obj, views in views_by_obj.items():
            for v in views:
                item_actions.append(self._action(
                    f'{obj};{v["name"]}', self._LIST_MANAGER,
                    {'filterName': v['name'], 'entityName': obj, 'pageSize': 50,
                     'layoutType': 'LIST', 'getCount': True, 'enableRowActions': False, 'offset': 0}
                ))

        accessible: set = set()
        for r in self._call(item_actions):
            try:
                obj, _ = r.action_id.split(';', 1)
                if r.ok and r.payload.get('recordIdActionsList'):
                    accessible.add(f'{self.app_url}/recordlist/{obj}/Default')
            except Exception:
                logger.debug('Error parsing UI list result')

        if accessible:
            logger.warning(f'{len(accessible)} accessible UI record list URLs — verify manually')
        return list(accessible)

    def fetch_home_urls(self) -> dict:
        logger.verbose('Fetching object home URLs')
        rs = self._call(self._action('17;a', self._BOOTSTRAP))
        if rs and rs[0].ok and rs[0].raw:
            try:
                components = rs[0].raw.get('components') or []
                urls = components[0]['model']['apiNameToObjectHomeUrls']
                logger.warning(f'{len(urls)} object home URLs — verify manually for sensitive panels')
                return urls
            except Exception:
                logger.debug('Could not extract home URLs from response')
        elif rs and not rs[0].ok:
            logger.verbose(f'Home URLs unavailable: {rs[0].error}')
        return {}

    def probe_self_registration(self):
        logger.verbose('Checking self-registration')
        rs = self._call([
            self._action('1', self._SELF_REG_CHECK),
            self._action('2', self._SELF_REG_URL),
        ])
        if len(rs) >= 2 and rs[0].ok and rs[0].payload:
            url = rs[1].payload if rs[1].ok else 'unknown'
            logger.warning(f'Self-registration is ENABLED — URL: {url}')
            return url
        logger.info('Self-registration not enabled')
        return None

    def probe_graphql(self):
        logger.verbose('Checking GraphQL availability')
        rs = self._call(self._action('GraphQL', self._GRAPHQL_ACTION, {
            'queryInput': {
                'operationName': 'getUsersCount',
                'query':         'query getUsersCount{uiapi{query{User{totalCount}}}}',
                'variables':     {},
            }
        }))
        if not rs:
            return
        r = rs[0]
        if r.ok:
            if r.payload.get('errors'):
                logger.debug(f'GraphQL present but restricted: {r.payload["errors"]}')
            else:
                logger.verbose('GraphQL available — will use it for record retrieval')
                self.gql_ok = True
        elif not r.ok:
            logger.verbose(f'GraphQL not available: {r.error}')

    def _fetch_field_map(self, objects) -> Optional[dict]:
        logger.verbose('Retrieving field names via GraphQL')
        banned_fields = {'CloneSourceId'}
        banned_types  = {'ADDRESS', 'ANYTYPE', 'COMPLEXVALUE'}
        field_map: dict = {}

        for batch in _chunks(objects, 100):
            names = json.dumps(batch, separators=(',', ':'))
            rs    = self._call(self._action('1;fields', self._GRAPHQL_ACTION, {
                'queryInput': {
                    'operationName': 'getFields',
                    'query':         f'query getFields{{uiapi{{objectInfos(apiNames:{names}){{ApiName,fields{{ApiName,dataType}}}}}}}}',
                    'variables':     {},
                }
            }))
            if not rs or not rs[0].ok:
                logger.error('GraphQL field retrieval failed')
                return None
            for info in filter(None, rs[0].payload['data']['uiapi']['objectInfos']):
                field_map[info['ApiName']] = [
                    f['ApiName'] for f in info['fields']
                    if f['dataType'] not in banned_types
                    and f['ApiName'] not in banned_fields
                ]

        return field_map

    def _count_with_graphql(self, objects) -> dict:
        """Count records per object via GraphQL, using a deque for retry on validation errors."""
        logger.verbose('Counting records via GraphQL')
        count_map : dict        = {}
        pending   : deque       = deque(_chunks(objects, 10))
        singles   : deque       = deque()

        def _build_count_action(chunk):
            q = ''.join(f'{obj}{{totalCount}}' for obj in chunk)
            return self._action('1;a', self._GRAPHQL_ACTION, {
                'queryInput': {'operationName': 'getCount',
                               'query': f'query getCount{{uiapi{{query{{{q}}}}}}}',
                               'variables': {}}
            })

        queues = [pending, singles]
        for queue in queues:
            while queue:
                chunk = queue.popleft()
                try:
                    rs = self._call([_build_count_action(chunk)],
                                    chunk_size=1 if queue is singles else 100)
                except requests.exceptions.ReadTimeout:
                    logger.error(f'Timeout counting {chunk}, skipping')
                    for obj in chunk:
                        count_map[obj] = -1
                    continue

                if not rs or rs[0].payload is None:
                    continue

                raw_str    = json.dumps(rs[0].payload)
                query_data = rs[0].payload.get('data', {}).get('uiapi', {}).get('query', {})

                for obj, val in query_data.items():
                    if val is not None:
                        count_map[obj] = val['totalCount']
                    else:
                        for err in rs[0].payload.get('errors', []):
                            if 'OPERATION_TOO_LARGE' in err.get('message', '') \
                               and len(err.get('paths', [])) == 3 \
                               and err['paths'][2] == obj:
                                count_map[obj] = -1
                            else:
                                logger.debug(f'Skipping {obj}: {err.get("message")}')

                if 'ValidationError' in raw_str and queue is pending:
                    pattern = r'FieldUndefined:[^\'"]+[\'"]([^\'"]+)[\'"]'
                    for field in re.findall(pattern, raw_str):
                        for c in list(pending) + [chunk]:
                            if field in c:
                                singles.append([field])

        return count_map

    def _iter_graphql_records(self, obj, fields, total, per_page=200) -> Iterator:
        """Generator — yields batches of records for one object via GraphQL cursor pagination."""
        cursor = None
        fetched = 0
        while fetched < total:
            field_str = ' '.join(f'{f}{{value}}' for f in fields)
            after     = f', after: "{cursor}"' if cursor else ''
            query_body = (
                f'{obj}(first: {per_page}{after}){{'
                f'edges{{node{{{field_str}}}}}'
                f'pageInfo{{hasNextPage endCursor}}'
                f'}}'
            )
            op = f'get{obj}Records'
            rs = self._call([self._action('1;a', self._GRAPHQL_ACTION, {
                'queryInput': {
                    'operationName': op,
                    'query':         f'query {op}{{uiapi{{query{{{query_body}}}}}}}',
                    'variables':     {},
                }
            })])
            if not rs or not rs[0].ok or 'data' not in rs[0].payload:
                break
            qdata     = rs[0].payload['data']['uiapi']['query'].get(obj, {})
            edges     = qdata.get('edges', [])
            page_info = qdata.get('pageInfo', {})
            records   = [
                {f: node[f]['value'] for f in fields if f in node and node[f] is not None}
                for edge in edges
                for node in [edge.get('node', {})]
            ]
            if not records:
                break
            yield records
            fetched += len(records)
            if not page_info.get('hasNextPage'):
                break
            cursor = page_info.get('endCursor')

    def collect_graphql_records(self, objects, per_page=200, fetch_all=True) -> dict:
        field_map = self._fetch_field_map(objects)
        if field_map is None:
            return {}
        gql_objects = list(field_map.keys())
        logger.info(f'{len(gql_objects)} objects accessible via GraphQL')
        logger.info('Counting records — this may take a moment…')

        count_map = self._count_with_graphql(gql_objects)
        results   = {obj: {'records': [], 'total_count': cnt}
                     for obj, cnt in count_map.items() if cnt != 0}
        total_records = sum(v['total_count'] for v in results.values() if v['total_count'] != -1)
        logger.info(f'{len(results)} objects with records ({total_records} total)')

        if not fetch_all:
            return results

        for obj, entry in results.items():
            if obj not in field_map:
                continue
            all_records: list = []
            try:
                for batch in self._iter_graphql_records(obj, field_map[obj],
                                                        entry['total_count'], per_page):
                    all_records.extend(batch)
            except Exception:
                logger.debug(f'Error collecting GraphQL records for {obj}')
                logger.debug(traceback.format_exc())
            entry['records'] = all_records
            logger.verbose(f'{obj}: {len(all_records)} records fetched')

        return results

    def scan_controllers(self) -> dict:
        parsed = urlparse(self.app_url)
        base   = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
        text   = self.session.get(base).text

        src_pat        = r'src="([^"]*)"'
        cmd_pat        = r'/auraCmdDef\?[^"\'"]+'
        controller_pat = r'apex://[a-zA-Z0-9_-]+/ACTION\$[a-zA-Z0-9_-]+'

        endpoints  = re.findall(src_pat, text) + re.findall(cmd_pat, text)
        found: dict = {}
        logger.verbose('Scanning discovered endpoints for custom controllers')

        for ep in endpoints:
            url = ep if ep.startswith('http') else f'{parsed.scheme}://{parsed.netloc}{ep}'
            try:
                hits = re.findall(controller_pat, self.session.get(url).text)
                if hits:
                    found[url] = list(set(found.get(url, []) + hits))
            except Exception:
                logger.debug(f'Error scanning {url}')

        total = sum(len(v) for v in found.values())
        logger.warning(f'Found {total} custom controllers') if total else logger.error('No custom controllers found')
        return found

    def probe_soap(self):
        logger.verbose('Checking SOAP API')
        try:
            r = self.session.post(f'{self.base}/services/Soap/u/35.0',
                                  headers={'Content-Type': 'text/xml', 'SOAPAction': 'Empty'})
            if r.status_code == 500 and 'text/xml' in r.headers.get('Content-Type', ''):
                logger.info('SOAP API appears exposed (requires username/password)')
            else:
                logger.info('SOAP API does not appear to be exposed')
        except Exception:
            logger.error('Error checking SOAP API')
            logger.debug(traceback.format_exc())

    def probe_rest(self) -> bool:
        logger.verbose('Checking REST API')
        try:
            latest = self.session.get(f'{self.base}/services/data').json()[-1]['url']
        except Exception:
            logger.error('Could not retrieve REST version list')
            logger.debug(traceback.format_exc())
            return False
        sid = self.session.cookies.get('sid')
        try:
            r = self.session.get(f'{self.base}{latest}',
                                 headers={'Authorization': f'Bearer {sid}'})
            accessible = r.status_code == 200
            msg = 'accessible' if accessible else 'not accessible'
            logger.info(f'REST API {msg} with provided SID')
            return accessible
        except Exception:
            logger.error('Error checking REST API')
            logger.debug(traceback.format_exc())
        return False


# ─── HTML report ──────────────────────────────────────────────────────────────

def build_html_report(target_url, scan_time, records, gql_records, permissions,
                      controllers, csp_sites, record_lists, home_urls) -> str:

    def _esc(s):
        return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def _perm_badge(val):
        if val:
            return '<span class="badge danger">YES</span>'
        return '<span class="badge muted">—</span>'

    def _count_badge(n):
        if n == -1:
            return '<span class="badge warn">?</span>'
        if n == 0:
            return '<span class="badge muted">0</span>'
        return f'<span class="badge ok">{n}</span>'

    def _section(title, body, id_attr=''):
        return f'<section id="{id_attr}">\n<h2>{title}</h2>\n{body}\n</section>\n'

    def _table(headers, rows, empty_msg='No data available.'):
        if not rows:
            return f'<p class="empty">{empty_msg}</p>'
        ths = ''.join(f'<th>{h}</th>' for h in headers)
        trs = ''
        for row in rows:
            trs += '<tr>' + ''.join(f'<td>{c}</td>' for c in row) + '</tr>'
        return f'<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>'

    def _flatten(rec, _depth=0):
        """Normalize any Salesforce record structure to a flat {field: str} dict."""
        if not isinstance(rec, dict) or _depth > 4:
            return {}
        # Aura: rec['fields'][field] = {'value': ..., 'displayValue': ...}
        if 'fields' in rec and isinstance(rec.get('fields'), dict):
            flat = {'Id': rec['id']} if 'id' in rec else {}
            for field, fdata in rec['fields'].items():
                if isinstance(fdata, dict):
                    val = fdata.get('displayValue') or fdata.get('value')
                else:
                    val = fdata
                flat[field] = '' if val is None else str(val)
            return flat
        # Some Aura responses wrap the record in a 'record' key
        if 'record' in rec and isinstance(rec.get('record'), dict):
            return _flatten(rec['record'], _depth + 1)
        # Generic: each value may itself be {'value': ...} (field-level wrapper)
        flat = {}
        for k, v in rec.items():
            if isinstance(v, dict):
                # field-level value wrapper
                if 'value' in v or 'displayValue' in v:
                    val = v.get('displayValue') or v.get('value')
                    flat[k] = '' if val is None else str(val)
                else:
                    # nested sub-object — recurse one level
                    sub = _flatten(v, _depth + 1)
                    flat.update({f'{k}.{sk}': sv for sk, sv in sub.items()})
            elif isinstance(v, list):
                pass  # skip relationship lists
            else:
                flat[k] = '' if v is None else str(v)
        return flat

    # ── Build sections ────────────────────────────────────────────────────────

    # Summary table
    summary_rows = []
    for obj, data in sorted(records.items()):
        cnt = data['total_count']
        if cnt > 0:
            summary_rows.append([_esc(obj), _count_badge(cnt),
                                 f'{len(data["records"])} fetched'])
    sections = _section('Record Summary (Aura)',
                        _table(['Object', 'Total Count', 'Fetched'], summary_rows,
                               'No accessible records found.'), 'summary')

    # GraphQL summary
    gql_rows = []
    for obj, data in sorted(gql_records.items()):
        cnt = data['total_count']
        if cnt != 0:
            gql_rows.append([_esc(obj), _count_badge(cnt),
                             f'{len(data["records"])} fetched'])
    if gql_rows:
        sections += _section('Record Summary (GraphQL)',
                             _table(['Object', 'Total Count', 'Fetched'], gql_rows), 'gql')

    # Permissions
    perm_rows = [
        [_esc(obj),
         _perm_badge(v['createable']),
         _perm_badge(v['updateable']),
         _perm_badge(v['deletable'])]
        for obj, v in sorted(permissions.items())
        if any(v.values())
    ]
    sections += _section('Object Permissions',
                         _table(['Object', 'Create', 'Update', 'Delete'], perm_rows,
                                'No write/delete permissions found.'), 'permissions')

    # Record details (collapsible per object)
    record_details = ''
    all_obj_records: dict = {}
    for source_label, source in [('Aura', records), ('GQL', gql_records)]:
        for obj, data in source.items():
            recs = data.get('records') or []
            if not recs and data.get('_raw'):
                recs = _extract_records(data['_raw'])
            if recs:
                key = f'{obj} ({source_label})' if obj in all_obj_records else obj
                all_obj_records[key] = recs

    for obj, recs in sorted(all_obj_records.items()):
        total = len(recs)
        flat_recs = [_flatten(r) for r in recs]
        flat_recs = [r for r in flat_recs if r]   # drop empties

        if flat_recs:
            # Derive columns from first 10 records to catch all field names
            cols = list(dict.fromkeys(k for r in flat_recs[:10] for k in r.keys()))
            header_row = ''.join(f'<th>{_esc(c)}</th>' for c in cols)
            data_rows  = ''
            for rec in flat_recs[:1000]:
                data_rows += '<tr>' + ''.join(
                    f'<td>{_esc(rec.get(c, ""))}</td>' for c in cols
                ) + '</tr>'
            shown = min(len(flat_recs), 1000)
            note  = f' <span class="badge warn">showing {shown} of {total}</span>' if total > 1000 else ''
            record_details += (
                f'<details open><summary>{_esc(obj)} — {total} records{note}</summary>'
                f'<div class="detail-body">'
                f'<div class="rec-toolbar">'
                f'<input class="rec-search" placeholder="Filter records…" '
                f'oninput="filterTable(this)" />'
                f'</div>'
                f'<div class="table-wrap">'
                f'<table><thead><tr>{header_row}</tr></thead>'
                f'<tbody>{data_rows}</tbody></table>'
                f'</div></div></details>\n'
            )
        else:
            # Fallback: _flatten could not parse the structure — show raw JSON
            raw_json = _esc(json.dumps(recs[:50], indent=2))
            note = (f' <span class="badge warn">showing 50 of {total}</span>'
                    if total > 50 else '')
            record_details += (
                f'<details open><summary>{_esc(obj)} — {total} records (raw){note}</summary>'
                f'<div class="detail-body">'
                f'<div class="table-wrap">'
                f'<pre style="margin:0;padding:1rem;font-size:0.78rem;'
                f'white-space:pre-wrap;word-break:break-all;color:var(--text);">'
                f'{raw_json}</pre>'
                f'</div></div></details>\n'
            )
    if record_details:
        toggle_btn = (
            '<button onclick="toggleAll()" style="margin-bottom:1rem;'
            'padding:0.4rem 1rem;background:var(--surface);color:var(--text);'
            'border:1px solid var(--border);border-radius:4px;cursor:pointer;">'
            'Collapse all</button>\n'
        )
        sections += _section('Fetched Records', toggle_btn + record_details, 'records')

    # Custom controllers
    ctrl_html = ''
    for url, ctrls in controllers.items():
        tags = ''.join(f'<span class="tag">{_esc(c)}</span>' for c in ctrls)
        ctrl_html += f'<p><code>{_esc(url)}</code></p><p>{tags}</p><br>'
    sections += _section('Custom Controllers',
                         ctrl_html or '<p class="empty">None found.</p>', 'controllers')

    # CSP trusted sites
    csp_tags = ''.join(f'<span class="tag">{_esc(s)}</span>'
                       for s in (csp_sites if isinstance(csp_sites, list)
                                 else [f'{k}: {v}' for k, v in csp_sites.items()]))
    sections += _section('CSP Trusted Sites',
                         csp_tags or '<p class="empty">None found.</p>', 'csp')

    # Record list URLs
    rl_items = ''.join(f'<li><a href="{_esc(u)}" target="_blank">{_esc(u)}</a></li>'
                       for u in record_lists)
    sections += _section('Accessible Record List URLs',
                         f'<ul>{rl_items}</ul>' if rl_items
                         else '<p class="empty">None found.</p>', 'lists')

    # Object home URLs
    hu_items = ''
    if isinstance(home_urls, dict):
        for obj, url in home_urls.items():
            hu_items += f'<li><strong>{_esc(obj)}</strong>: <a href="{_esc(url)}" target="_blank">{_esc(url)}</a></li>'
    if hu_items:
        sections += _section('Object Home URLs', f'<ul>{hu_items}</ul>', 'homeurls')
    else:
        sections += _section('Object Home URLs', '<p class="empty">None found.</p>', 'homeurls')

    # ── Assemble page ─────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SFScout Report — {_esc(target_url)}</title>
<style>
  :root {{
    --bg:      #0f1117;
    --surface: #1a1d27;
    --border:  #2d3047;
    --accent:  #4f8ef7;
    --text:    #e2e8f0;
    --muted:   #718096;
    --red:     #fc8181;
    --orange:  #f6ad55;
    --green:   #68d391;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px; line-height: 1.6;
  }}
  a {{ color: var(--accent); }}
  header {{
    padding: 2rem 2.5rem;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 1.5rem;
  }}
  header h1 {{ font-size: 1.4rem; color: var(--accent); font-weight: 700; }}
  .meta {{ color: var(--muted); font-size: 0.82rem; margin-top: 0.3rem; }}
  nav {{
    padding: 0.75rem 2.5rem;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    font-size: 0.82rem;
    display: flex; gap: 1.5rem; flex-wrap: wrap;
  }}
  nav a {{ color: var(--muted); text-decoration: none; }}
  nav a:hover {{ color: var(--text); }}
  main {{ max-width: 1280px; margin: 0 auto; padding: 2rem 2.5rem; }}
  section {{
    margin-bottom: 2.5rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}
  section h2 {{
    font-size: 0.9rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--muted);
    padding: 0.8rem 1.25rem;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }}
  section > *:not(h2) {{ padding: 1.25rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{
    text-align: left; padding: 0.5rem 1rem;
    background: var(--surface);
    border-bottom: 2px solid var(--border);
    color: var(--muted); font-size: 0.75rem;
    text-transform: uppercase; letter-spacing: 0.05em;
  }}
  td {{ padding: 0.45rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .badge {{
    display: inline-block; padding: 0.1rem 0.5rem;
    border-radius: 4px; font-size: 0.75rem; font-weight: 600;
  }}
  .badge.danger  {{ background: rgba(252,129,129,.15); color: var(--red); }}
  .badge.warn    {{ background: rgba(246,173, 85,.15); color: var(--orange); }}
  .badge.ok      {{ background: rgba(104,211,145,.15); color: var(--green); }}
  .badge.muted   {{ background: rgba(113,128,150,.10); color: var(--muted); }}
  details {{
    border-top: 1px solid var(--border);
  }}
  details:first-of-type {{ border-top: none; }}
  summary {{
    padding: 0.75rem 1.25rem;
    cursor: pointer;
    font-size: 0.88rem; font-weight: 500;
    background: var(--surface);
    user-select: none;
  }}
  summary:hover {{ background: var(--border); }}
  details[open] summary {{ border-bottom: 1px solid var(--border); }}
  .detail-body {{ padding: 0; }}
  .table-wrap {{ overflow-x: auto; max-height: 500px; overflow-y: auto; }}
  .tag {{
    display: inline-block;
    background: var(--surface); border: 1px solid var(--border);
    padding: 0.15rem 0.5rem; border-radius: 4px;
    font-size: 0.75rem; margin: 0.15rem; font-family: monospace;
  }}
  code {{ font-family: monospace; font-size: 0.8rem; color: var(--muted); }}
  .empty {{ color: var(--muted); font-style: italic; font-size: 0.88rem; }}
  ul {{ padding-left: 1.25rem; }}
  li {{ margin-bottom: 0.3rem; font-size: 0.85rem; }}
  p {{ margin-bottom: 0.5rem; }}
  .rec-toolbar {{
    padding: 0.75rem 1.25rem 0;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }}
  .rec-search {{
    width: 100%; max-width: 400px;
    padding: 0.4rem 0.75rem;
    background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 4px;
    font-size: 0.85rem; margin-bottom: 0.75rem;
  }}
  .rec-search:focus {{ outline: none; border-color: var(--accent); }}
  tr.hidden {{ display: none; }}
  @media (max-width: 700px) {{
    header, main, nav {{ padding-left: 1rem; padding-right: 1rem; }}
  }}
</style>
<script>
  function filterTable(input) {{
    var q = input.value.toLowerCase();
    var tbody = input.closest('details').querySelector('tbody');
    tbody.querySelectorAll('tr').forEach(function(row) {{
      row.classList.toggle('hidden', !row.textContent.toLowerCase().includes(q));
    }});
  }}
  function toggleAll() {{
    var details = document.querySelectorAll('#records details');
    var allOpen = Array.from(details).every(function(d) {{ return d.open; }});
    details.forEach(function(d) {{ d.open = !allOpen; }});
    document.querySelector('#records button').textContent = allOpen ? 'Expand all' : 'Collapse all';
  }}
</script>
</head>
<body>
<header>
  <div>
    <h1>SFScout — Scan Report</h1>
    <div class="meta">
      Target: <strong>{_esc(target_url)}</strong>
      &nbsp;·&nbsp;
      Scanned: <strong>{_esc(scan_time)}</strong>
      &nbsp;·&nbsp;
      v{TOOL_VERSION}
    </div>
  </div>
</header>
<nav>
  <a href="#summary">Summary</a>
  <a href="#permissions">Permissions</a>
  <a href="#records">Records</a>
  <a href="#controllers">Controllers</a>
  <a href="#csp">CSP</a>
  <a href="#lists">Record Lists</a>
  <a href="#homeurls">Home URLs</a>
</nav>
<main>
{sections}
</main>
</body>
</html>
"""


# ─── CLI output helpers ────────────────────────────────────────────────────────

def tabulate_counts(records) -> str:
    rows      = [('Object', 'Count')]
    col_width = 15
    for obj, data in records.items():
        cnt = data['total_count']
        if cnt == 0:
            continue
        col_width = max(col_width, len(obj) + 1)
        rows.append((obj, str(cnt) if cnt != -1 else 'Unknown'))
    return '\n'.join(''.join(f'{c:<{col_width}}' for c in row) for row in rows)


def tabulate_permissions(permissions) -> str:
    if not permissions:
        return '  No permission data\n'
    col = max(15, max(len(k) + 1 for k in permissions))
    fw  = 8
    out = f'{"Object":<{col}}{"Create":<{fw}}{"Update":<{fw}}{"Delete":<{fw}}\n'
    for obj, v in sorted(permissions.items()):
        if any(v.values()):
            out += (f'{obj:<{col}}'
                    f'{"YES" if v["createable"] else "-":<{fw}}'
                    f'{"YES" if v["updateable"] else "-":<{fw}}'
                    f'{"YES" if v["deletable"]  else "-":<{fw}}\n')
    return out or '  No write/delete permissions found\n'


# ─── File output ──────────────────────────────────────────────────────────────

def save_records(records, parent, sub):
    if not records:
        return
    path = os.path.join(parent, sub)
    os.makedirs(path, exist_ok=True)
    logger.info(f'Writing records → {path}')
    with open(os.path.join(path, 'summary.txt'), 'w') as f:
        f.write(tabulate_counts(records))
    for obj, data in records.items():
        if not data.get('total_count'):
            continue
        rows = data.get('records') or []
        dump = rows or data.get('_raw')
        if dump:
            fp = os.path.join(path, f'{obj}.json')
            with open(fp, 'w') as f:
                json.dump(dump, f, indent=2)
            logger.info(f'  {obj}: {len(rows)} records → {fp}')


def save_misc(data, parent, sub='misc', filename=''):
    if not data:
        return
    path = os.path.join(parent, sub)
    os.makedirs(path, exist_ok=True)
    fp   = os.path.join(path, filename)
    logger.info(f'Writing misc → {fp}')
    with open(fp, 'w') as f:
        json.dump(data, f, indent=2)


# ─── Orchestration ────────────────────────────────────────────────────────────

def run_scan(url, cookies, object_list, output_dir, proxy, fetch_max_data=False,
             insecure=False, app=None, aura_path=None, context=None,
             token='null', no_gql=False, html_output=False):

    probe = AuraProbe(url=url, cookies=cookies, proxy=proxy, insecure=insecure,
                      app=app, aura=aura_path, context=context, token=token)

    probe.probe_self_registration()
    probe.probe_rest()
    probe.probe_soap()
    if not no_gql:
        probe.probe_graphql()

    controllers  = probe.scan_controllers()
    all_objects  = probe.fetch_objects()
    objects      = all_objects

    if object_list:
        lower_all = [o.lower() for o in all_objects]
        valid     = [o for o in object_list if o.lower() in lower_all]
        invalid   = [o for o in object_list if o.lower() not in lower_all]
        if not valid:
            logger.error('None of the specified objects were found on the target')
            sys.exit(1)
        objects = valid
        logger.info(f'Targeting {len(valid)} specified objects')
        if invalid:
            logger.warning(f'Ignoring unrecognised: {", ".join(invalid)}')

    if not objects:
        logger.error('No objects to scan')
        sys.exit(1)

    records     : dict = {}
    gql_records : dict = {}

    if not fetch_max_data:
        records = probe.collect_records(objects)
        if probe.gql_ok:
            gql_records = probe.collect_graphql_records(objects, fetch_all=True)

    record_lists = probe.fetch_ui_lists(objects)
    home_urls    = probe.fetch_home_urls()
    permissions  = probe.check_permissions(objects)

    print('\n--- Summary (Aura) ---')
    print(tabulate_counts(records))
    if probe.gql_ok:
        print('\n--- Summary (GraphQL) ---')
        print(tabulate_counts(gql_records))
    print('\n--- Permissions ---')
    print(tabulate_permissions(permissions))

    if not output_dir:
        while True:
            choice = input('\nSave results? (y/N): ').strip()
            if choice == 'y':
                output_dir = input('Output directory: ').strip()
                break
            elif choice == 'N':
                logger.warning('Results not saved')
                break
            else:
                logger.warning('Enter y or N')

    if output_dir:
        save_records(records,     output_dir, 'records')
        save_records(gql_records, output_dir, 'gql_records')
        save_misc(record_lists,   output_dir, filename='recordlists.json')
        save_misc(home_urls,      output_dir, filename='homeurls.json')
        save_misc(probe.csp_sites, output_dir, filename='csp_trusted_sites.json')
        save_misc(controllers,    output_dir, filename='custom_controllers.json')
        save_misc(permissions,    output_dir, filename='permissions.json')
        logger.info(f'Results saved to {output_dir}')

        if html_output:
            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            html = build_html_report(
                target_url=url,
                scan_time=scan_time,
                records=records,
                gql_records=gql_records,
                permissions=permissions,
                controllers=controllers,
                csp_sites=probe.csp_sites,
                record_lists=record_lists,
                home_urls=home_urls,
            )
            html_path = os.path.join(output_dir, 'report.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f'HTML report saved to {html_path}')


# ─── Request file parser ──────────────────────────────────────────────────────

def parse_request_file(path) -> dict:
    with open(path, 'r') as f:
        lines = [l.strip() for l in f.readlines()]

    request_line  = lines[0]
    aura_endpoint = request_line.split(' ')[1].split('?')[0]

    if not ('aura' in aura_endpoint and 'POST' in request_line):
        logger.warning('File may not be a POST request to an Aura endpoint')

    headers: dict = {}
    for line in lines[1:]:
        if not line:
            break
        key, _, val = line.partition(':')
        k = key.lower().strip()
        if k == 'host':
            headers['host'] = val.strip()
        elif k == 'cookie':
            headers['cookies'] = val.strip()

    body = parse_qs(lines[-1])
    return {
        'url':           'https://' + headers['host'],
        'cookies':       headers.get('cookies', ''),
        'context':       body['aura.context'][0],
        'aura_endpoint': aura_endpoint,
        'token':         body['aura.token'][0],
    }


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='sfscout',
        description='Salesforce Experience Cloud security auditing tool'
    )
    parser.add_argument('-u', '--url',               help='Root URL of the Salesforce application')
    parser.add_argument('-c', '--cookies',           help='Session cookies', default=None)
    parser.add_argument('-o', '--output-dir',        help='Output directory', default=None)
    parser.add_argument('-l', '--object-list',       help='Comma-separated objects to target', default=None)
    parser.add_argument('-d', '--debug',             help='Debug output', action='store_const', const=True, default=False)
    parser.add_argument('-v', '--verbose',           help='Verbose output', action='store_const', const=True, default=False)
    parser.add_argument('-p', '--proxy',             help='HTTP/S proxy URL', default=None)
    parser.add_argument('-k', '--insecure',          help='Skip TLS verification', action='store_true')
    parser.add_argument('--app',                     help='App path (e.g. /myApp)')
    parser.add_argument('--aura',                    help='Aura endpoint path (e.g. /aura)')
    parser.add_argument('--context',                 help='Custom aura.context value')
    parser.add_argument('--token',                   help='Custom aura.token value')
    parser.add_argument('--no-gql',                  help='Skip GraphQL checks', action='store_true')
    parser.add_argument('--no-banner',               help='Suppress banner', action='store_true')
    parser.add_argument('--html',                    help='Generate HTML report in output directory', action='store_true')
    parser.add_argument('-r', '--aura-request-file', help='Path to a captured HTTP request file')

    args = parser.parse_args()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(0)

    add_logging_level('VERBOSE', 15)
    level = logging.DEBUG if args.debug else logging.VERBOSE if args.verbose else logging.INFO
    init_logger(level)

    if not args.no_banner:
        logger.warning(r'''
  ____  _____ ____                 _
 / ___||  ___/ ___|  ___ ___  _   _| |_
 \___ \| |_  \___ \ / __/ _ \| | | | __|
  ___) |  _|  ___) | (_| (_) | |_| | |_
 |____/|_|   |____/ \___\___/ \__,_|\__|

 Salesforce Experience Cloud Security Auditor
        ''')

    url, app, cookies, aura, token, context = (
        args.url, args.app, args.cookies, args.aura, args.token, args.context
    )

    if args.aura_request_file:
        parsed  = parse_request_file(args.aura_request_file)
        url     = parsed['url']
        aura    = parsed['aura_endpoint']
        context = parsed['context']
        cookies = parsed['cookies']
        token   = parsed['token']
    else:
        if not url:
            logger.error('Provide a target URL with -u or a request file with -r')
            sys.exit(1)
        url = url.rstrip('/')
        if url.endswith('/s'):
            logger.warning('URL ends with /s — if scanning fails, try the root URL instead')

    if app == '/':
        app = '/s'

    object_list = [o.strip() for o in args.object_list.split(',')] if args.object_list else None

    if args.html and not args.output_dir:
        logger.error('--html requires --output-dir (-o) to be specified')
        sys.exit(1)

    run_scan(
        url,
        cookies=cookies,
        object_list=object_list,
        output_dir=args.output_dir,
        proxy=args.proxy,
        insecure=args.insecure,
        app=app,
        aura_path=aura,
        context=context,
        token=token,
        no_gql=args.no_gql,
        html_output=args.html,
    )


if __name__ == '__main__':
    main()
