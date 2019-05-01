#!venv/bin/python3

import argparse
import datetime
import json
import os
import requests
import sys

from dotenv import load_dotenv
load_dotenv()


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class AuthException(Exception):
    pass


class APIException(Exception):

    def __init__(self, message=None, status_code=None, errors=None, url=None, method=None):
        if errors and not message:
            message = json.dumps(errors)
        super(APIException, self).__init__(message)
        self.message = message
        self.status_code = status_code
        self.errors = errors or []
        self.url = url
        self.method = method

    @property
    def human_str(self):
        return 'API Error: {msg:s}\n{method:s}: {url:s}\nHTTP Status: {status}\nError Detail:\n{detail}'.format(
            msg=self.__str__(),
            status=self.status_code or '[unknown]',
            detail=json.dumps(self.errors, sort_keys=True, indent=2),
            method='HTTP {}'.format(self.method or '[unknown method]'),
            url=self.url or '[URL unknown]'
        )


class NameDotcomAPI(object):

    API_BASE = 'https://api.name.com/v4'

    def __init__(self, username, token):
        self.auth = (username, token)

    def _check_response(self, r):
        if r.status_code in (401, 403):
            raise AuthException()
        if r.status_code not in (200, 201, 202, 203, 204):
            decoded = r.json()
            raise APIException(
                message=decoded.get('message'),
                status_code=r.status_code,
                method=r.request.method,
                errors=[decoded.get('details', 'no additional detail available')],
                url=r.request.url,
            )

    def _get(self, endpoint, params=None):
        url = '{base:s}/{endpoint:s}'.format(base=NameDotcomAPI.API_BASE, endpoint=endpoint)
        resp = requests.get(url, auth=self.auth, params=params)
        self._check_response(resp)
        return resp

    def _post(self, endpoint, json_body=None, params=None):
        url = '{base:s}/{endpoint:s}'.format(base=NameDotcomAPI.API_BASE, endpoint=endpoint)
        resp = requests.post(url, auth=self.auth, json=json_body, params=params)
        self._check_response(resp)
        return resp

    def _get_all_pages(self, endpoint, params=None):
        if params is None:
            params = {}
        params['page'] = 1
        resp = self._get(endpoint, params)
        results = resp.json()
        next_url = resp.links.get('next')
        while next_url:
            resp = requests.get(next_url, auth=self.auth)
            self._check_response(resp)
            results.extend(resp.json())
            next_url = resp.links.get('next')
        return results

    def _get_decoded(self, endpoint, params=None):
        return self._get(endpoint, params).json()

    def _post_decoded(self, endpoint, json_body=None, params=None):
        return self._post(endpoint, json_body, params).json()

    def check_auth(self):
        return self._get_decoded('hello')

    def get_all_dns_records(self, domain):
        return self._get_all_pages('domains/{name:s}/records'.format(name=domain))['records']

    def create_record(self, domain, record):
        return self._post_decoded(
            endpoint='domains/{name:s}/records'.format(name=domain),
            json_body=record
        )

    def delete_record(self, domain, record_id):
        url = '{base:s}/domains/{name:s}/records/{id:d}'\
            .format(base=NameDotcomAPI.API_BASE, name=domain, id=record_id)
        resp = requests.delete(url, auth=self.auth)
        self._check_response(resp)
        return resp

    def set_nameservers(self, domain, nameservers):
        return self._post_decoded(
            endpoint='domains/{name:s}:setNameservers'.format(name=domain),
            json_body={'nameservers': nameservers}
        )


class HTTPBearerAuth(requests.auth.AuthBase):

    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return isinstance(other, HTTPBearerAuth) \
            and self.token == other.token

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = 'Bearer ' + self.token
        return r


class DigitalOceanAPI(object):

    API_BASE = 'https://api.digitalocean.com/v2'

    def __init__(self, token):
        self.auth = HTTPBearerAuth(token)

    def _check_response(self, r):
        if r.status_code in (401, 403):
            raise AuthException()
        if r.status_code not in (200, 201, 202, 203, 204):
            decoded = r.json()
            raise APIException(
                message=decoded.get('message'),
                status_code=r.status_code,
                method=r.request.method,
                errors=[decoded.get('id', 'no additional detail available')],
                url=r.request.url,
            )

    def _get(self, endpoint, params=None):
        url = '{base:s}/{endpoint:s}'.format(base=DigitalOceanAPI.API_BASE, endpoint=endpoint)
        resp = requests.get(url, auth=self.auth, params=params)
        self._log_ratelimit(resp)
        self._check_response(resp)
        return resp

    def _post(self, endpoint, json_body=None, params=None):
        url = '{base:s}/{endpoint:s}'.format(base=DigitalOceanAPI.API_BASE, endpoint=endpoint)
        resp = requests.post(url, auth=self.auth, json=json_body, params=params)
        self._log_ratelimit(resp)
        self._check_response(resp)
        return resp

    def _get_decoded(self, endpoint, params=None):
        return self._get(endpoint, params).json()

    def _post_decoded(self, endpoint, json_body=None, params=None):
        return self._post(endpoint, json_body, params).json()

    def _log_ratelimit(self, response):
        ratelimit = response.headers.get('RateLimit-Limit')
        remaining = response.headers.get('RateLimit-Remaining')
        reset = response.headers.get('RateLimit-Reset')
        if not ratelimit or not remaining or not reset:
            return
        reset_dt = datetime.datetime.utcfromtimestamp(int(reset.strip()))\
            .replace(tzinfo=datetime.timezone.utc)
        eprint("DO Rate Limit: {:s}/{:s} remain; reset {:s}".format(
            remaining, ratelimit, reset_dt.isoformat(' ')))

    def check_auth(self):
        return self._get_decoded('account')

    def create_domain(self, domain):
        return self._post_decoded(
            endpoint='domains',
            json_body={"name": domain}
        )

    def create_record(self, domain, record):
        return self._post_decoded(
            endpoint='domains/{name:s}/records'.format(name=domain),
            json_body=record
        )

    def get_all_dns_records(self, domain):
        return self._get_decoded('domains/{name:s}/records'.format(name=domain))['domain_records']


class Migrator(object):

    def __init__(self, namedotcom_api, do_api):
        self.namedotcom_api = namedotcom_api
        self.do_api = do_api

    def migrate(self, domain_name):
        domain_name = domain_name.lower().strip()
        source_records = self.namedotcom_api.get_all_dns_records(domain_name)
        try:
            do_api.create_domain(domain_name)
        except APIException as e:
            if e.status_code != 422 or "already exists" not in e.message:
                raise e
        for r in source_records:
            print('-------------------------')
            if r['type'] == 'ANAME':
                print("[!] ANAME records are not supported by DigitalOcean.")
                print("[!] Skipping migration of the following record:")
                print(json.dumps(r, indent=2))
                print("[!]")
                continue
            target_record = {
                'type': r['type'],
                'data': r['answer'],
                'ttl': r['ttl'],
            }
            if 'host' in r:
                target_record['name'] = r['host']
            elif r['type'] in ('A', 'AAAA', 'TXT'):
                target_record['name'] = '@'
            if r['type'] in ('CNAME', 'MX'):
                target_record['data'] = target_record['data'] + '.'
            if 'priority' in r:
                target_record['priority'] = r['priority']
            if r['type'] == 'SRV':
                # Parse name.com srv records from 'answer' field
                # "{weight} {port} {target}" e.g. "1 5061 sip.example.org"
                # use it to populate DO port, weight fields
                split = r['answer'].split(' ')
                try:
                    target_record['weight'] = int(split[0])
                    target_record['port'] = int(split[1])
                    target_record['data'] = split[2]
                except (IndexError, ValueError):
                    print("[!] Encountered a malformed SRV answer field.")
                    print("[!] Skipping migration of the following record:")
                    print(json.dumps(r, indent=2))
                    print("[!]")
                    continue
            print("Source record:")
            print(json.dumps(r, indent=2))
            print("Target record:")
            print(json.dumps(target_record, indent=2))
            print("Committing...")
            do_api.create_record(domain_name, target_record)
            print("Committed.")
        print('-------------------------')
        print("Setting ns*.digitalocean.com nameservers for {:s}.".format(domain_name))
        print("Committing...")
        do_ns = ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com']
        namedotcom_api.set_nameservers(domain_name, do_ns)
        print("Committed.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Migrate a domain's DNS records from Name.com to DigitalOcean.")
    parser.add_argument('domain', type=str, help='The domain to migrate.')
    args = parser.parse_args()

    name_user = os.getenv('NAME_DOTCOM_USERNAME')
    name_token = os.getenv('NAME_DOTCOM_API_TOKEN')
    if not name_user or not name_token:
        eprint("Name.com username & API token must be set using environment variables.")
        eprint("Copy .env.sample to .env and fill it out to provide credentials.")
        sys.exit(2)
    namedotcom_api = NameDotcomAPI(name_user, name_token)
    try:
        namedotcom_api.check_auth()
    except AuthException:
        eprint("Name.com authentication check failed.")
        eprint("Check your credentials and try again.")
        sys.exit(2)
    except APIException as e:
        eprint("Name.com authentication check failed.")
        eprint(e.human_str)
        sys.exit(2)

    do_token = os.getenv('DIGITALOCEAN_TOKEN')
    if not do_token:
        eprint("DigitalOcean API token must be set using an environment variable.")
        eprint("Copy .env.sample to .env and fill it out to provide credentials.")
        sys.exit(2)
    do_api = DigitalOceanAPI(do_token)
    try:
        do_api.check_auth()
    except AuthException:
        eprint("DigitalOcean authentication check failed.")
        eprint("Check your credentials and try again.")
        sys.exit(2)
    except APIException as e:
        eprint("DigitalOcean authentication check failed.")
        eprint(e.human_str)
        sys.exit(2)

    domain_name = args.domain.lower().strip()
    migrator = Migrator(namedotcom_api, do_api)
    try:
        migrator.migrate(domain_name)
        print("")
        print("Completed migration of {:s}".format(domain_name))
        print("")
        print("Current DNS records at DigitalOcean for {:s}:".format(domain_name))
        print(json.dumps(do_api.get_all_dns_records(domain_name), indent=2))
    except APIException as e:
        eprint(e.human_str)
        sys.exit(1)
    except AuthException:
        eprint("Check your credentials and try again.")
        sys.exit(2)
