"""Run and record the scheduled ad update without exposing subscription URLs."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import urllib.error

import ad_delivery
import ad_rules
import standard_rule_source
from storage import lock, save

STATUS = Path('/var/lib/argosbx-fleet/ad-update-status.json')
LOCK = Path('/run/argosbx-publisher.lock')


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def read_status(path=STATUS):
    if not path.exists():
        return {}
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('广告任务状态文件无效')
    return value


def error_detail(error):
    result = {'type': type(error).__name__}
    if isinstance(error, urllib.error.HTTPError):
        result['http_status'] = error.code
    if isinstance(error, ValueError):
        prefix = '投放后台可能被广告规则拦截：'
        message = str(error)
        host = message[len(prefix):] if message.startswith(prefix) else ''
        if host in ad_rules.CONSOLE_SAMPLES:
            result.update(reason='console-blocked', host=host)
        for start, reason in (('广告名单变动超过', 'upstream-change-limit'),
                              ('广告名单缺少', 'missing-ad-sample'),
                              ('发布期间文件发生变化', 'concurrent-change')):
            if message.startswith(start):
                result['reason'] = reason
    return result


def run(*, verify_only=False, status_path=None, lock_path=None):
    status_path = STATUS if status_path is None else Path(status_path)
    lock_path = LOCK if lock_path is None else Path(lock_path)
    with lock(lock_path):
        previous = read_status(status_path)
        started = timestamp()
        phase = 'configuration'
        def set_phase(value):
            nonlocal phase
            phase = value
        try:
            ad_delivery.check_onboarding()
            settings = ad_delivery.read_config(ad_delivery.CONFIG)
            phase = 'ad-rules'
            result = ad_delivery.refresh(settings, verify_only=verify_only, progress=set_phase)
            phase = 'standard-rules'
            standard = standard_rule_source.refresh_if_configured(verify=verify_only)
        except Exception as error:
            if not verify_only:
                state = {'last_success': previous.get('last_success'), 'last_attempt': started, 'result': 'failed',
                         'phase': phase, 'error': error_detail(error)}
                save(status_path, state)
                print(json.dumps({'event': 'ad-update', **state}, ensure_ascii=False), file=sys.stderr, flush=True)
            raise
        if verify_only:
            return {'verified': True, 'ad': result, 'standard': standard}
        state = {'last_attempt': started, 'last_success': timestamp(), 'result': 'success',
                 'domains': result['domains'], 'changed': result['changed'],
                 'standard_configured': standard.get('configured', False)}
        save(status_path, state)
        print(json.dumps({'event': 'ad-update', **state}, ensure_ascii=False), flush=True)
        return state


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='广告规则更新与本机状态')
    parser.add_argument('action', choices=('run', 'verify', 'status'))
    args = parser.parse_args()
    try:
        if args.action == 'status':
            print(json.dumps(read_status(), ensure_ascii=False))
        elif args.action == 'verify':
            print(json.dumps(run(verify_only=True), ensure_ascii=False))
        else:
            run()
    except Exception as error:
        # Error messages can contain a private subscription URL.
        print(json.dumps({'event': 'ad-update-error', **error_detail(error)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
