import requests
import os
import json
import re

class ReadmeApi(object):
    def __init__(self):
        super().__init__()
        self.doc_version = None

    def authenticate(self, api_key):
        r = requests.get('https://dash.readme.com/api/v1', auth=(api_key, ''))
        if r.status_code != 200:
            raise Exception('Failed to authenticate')
        auth_response = r.json()
        self.jwt = auth_response['jwtSecret']
        self.base_url = auth_response['baseUrl']
        self.api_key = api_key

    def set_version(self, version:str):
        self.doc_version = version

    def get_categories(self):
        url = "https://dash.readme.com/api/v1/categories"

        querystring = {"perPage":"1000","page":"1"}

        r = requests.request("GET", url, params=querystring, auth=(self.api_key, ''))

        if r.status_code != 200:
            raise Exception('Failed to get categories')

        return r.json()

    def get_category(self,category_slug : str):
        url = "https://dash.readme.com/api/v1/categories/%s" % category_slug

        r = requests.request("GET", url,headers={"Accept": "application/json"}, auth=(self.api_key, ''))

        if r.status_code != 200:
            raise Exception('Failed to get categories')

        return r.json()

    def get_docs_in_category(self, category_slug: str):
        url = "https://dash.readme.com/api/v1/categories/%s/docs" % category_slug

        r = requests.request("GET", url, headers={"Accept":"application/json"}, auth=(self.api_key, ''))

        if r.status_code != 200:
            raise Exception('Failed to docs for category')

        return r.json()

    def get_doc(self, doc_slug: str):
        url = "https://dash.readme.com/api/v1/docs/%s" % doc_slug

        r = requests.request("GET", url, headers={"Accept":"application/json"}, auth=(self.api_key, ''))

        if r.status_code == 404:
            return None
        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to docs for category')

        return r.json()

    def delete_doc(self, doc_slug: str):
        url = "https://dash.readme.com/api/v1/docs/%s" % doc_slug

        r = requests.request("DELETE", url, headers={"Accept":"application/json"}, auth=(self.api_key, ''))

        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to delete doc (%d)'%r.status_code)
    
    def create_doc(self, parent_id: str, order: int, title: str, body: str, category: str):
        url = "https://dash.readme.com/api/v1/docs"

        payload = {
            "hidden": False,
            "order": order,
            "title": title,
            "type": "basic",
            "body": body,
            "category": category,
            "parentDoc": parent_id
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        r = requests.request("POST", url, json=payload, headers=headers, auth=(self.api_key, ''))


        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to create doc: %s'%r.text)

        return r.json()
        
    def update_doc(self, doc_slug: str, order: int, title: str, body: str, category: str):

        url = "https://dash.readme.com/api/v1/docs/%s" % doc_slug

        payload = {
            "hidden": False,
            "order": order,
            "title": title,
            "body": body,
            "category": category
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        r = requests.request("PUT", url, json=payload, headers=headers, auth=(self.api_key, ''))

        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to update doc: %s'%r.text)

        return r.json()

def validate_readme_structure(readmeapi : ReadmeApi):
    categories = readmeapi.get_categories()
    filtered_categories = list(filter(lambda c: c['title'] == 'Controls',categories))
    if len(filtered_categories) != 1:
        raise Exception('Readme structure validation failure: missing "Controls" category (or more than one)')
    controls_category = filtered_categories[0]
    docs_in_control_category = readmeapi.get_docs_in_category(controls_category['slug'])
    filtered_docs = list(filter(lambda d: d['title'] == 'Controls',docs_in_control_category))
    if len(filtered_docs) != 1:
        raise Exception('Readme structure validation failure: missing "Controls" document')

def get_document_for_control(readmeapi : ReadmeApi, control):
    categories = readmeapi.get_categories()
    filtered_categories = list(filter(lambda c: c['title'] == 'Controls',categories))
    if len(filtered_categories) != 1:
        raise Exception('Readme structure failure: missing "Controls" category (or more than one)')
    controls_category = filtered_categories[0]
    docs_in_control_category = readmeapi.get_docs_in_category(controls_category['slug'])
    filtered_docs = list(filter(lambda d: d['title'].startswith(control['id']),docs_in_control_category))
    if len(filtered_docs) != 1:
        return None
    control_doc = filtered_docs[0]
    return control_doc



def get_frameworks_for_control(control):
    r = []
    for frameworks_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('frameworks')):
        framework = json.load(open(os.path.join('frameworks',frameworks_json_file_name)))
        if framework['name'].startswith('developer'):
            continue
        if control['name'] in framework['controlsNames']:
            r.append(framework['name'])
    return r
   

def create_md_for_control(control):
    md_text = ''
    md_text += '# %s\n' % control['name']
    md_text += '## Framework\n'
    md_text += ','.join(get_frameworks_for_control(control)) + '\n'
    md_text += '## Description of the the issue\n'
    description = control['long_description'] if 'long_description' in control else control['description']
    md_text += description + '\n'
    md_text += '## Related resources\n'
    scanned_objects = control['scanned_objects'] if 'scanned_objects' in control else ['none']
    md_text += ','.join(scanned_objects) + '\n'
    md_text += '## What does this control tests\n'
    test = control['test'] if 'test' in control else control['description']
    md_text += test + '\n'
    md_text += '## Remediation\n'
    md_text += control['remediation'] + '\n'
    md_text += '## Example\n'
    if 'example' in control:
        md_text += '```\n' +control['example'] + '```\n' + '\n'
    else:
        md_text += 'No example\n'
    return md_text

def generate_slug(control):
    fixed_name = control['name']
    for c in '/.()!@#$%^&*_+=[]{};:",':
        fixed_name = fixed_name.replace(c,'')
    slug = (control['id']+ ' ' + fixed_name).replace(' ','-').lower()
    slug = re.sub('-+','-',slug)
    return slug

def main():
    API_KEY = os.getenv('README_API_KEY')
    if not API_KEY:
        raise Exception('README_API_KEY is not defined')
    
    # Validate connection
    readmeapi = ReadmeApi()
    readmeapi.authenticate(API_KEY)
    print('Authenticated')

    # Validated structure
    validate_readme_structure(readmeapi)
    print('Readme structure validated')

    control_category_obj = readmeapi.get_category('controls')
    parent_control_doc = readmeapi.get_doc('controls')
    #print("Parent doc\n",parent_control_doc)
    if os.getenv('PRUNE_CONTROLS'):
        for control_doc in readmeapi.get_docs_in_category('controls'):
            if control_doc['_id'] == parent_control_doc['_id']:
                for child_doc in control_doc['children']:
                    readmeapi.delete_doc(child_doc['slug'])
                    print('Deleted %s'%child_doc['slug'])

    # Start processing
    for control_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('controls')):
        try:
            print('processing %s' % control_json_file_name)
            control_obj = json.load(open(os.path.join('controls',control_json_file_name)))
            md = create_md_for_control(control_obj)

            title = '%(id)s - %(name)s' % control_obj

            control_slug = generate_slug(control_obj)
            
            control_doc = readmeapi.get_doc(control_slug)

            if control_doc:
                readmeapi.update_doc(control_slug,int(control_obj['id'][2:]),title,md,control_category_obj['_id'])
                print('\tupdated')
            else:
                readmeapi.create_doc(parent_control_doc['_id'],int(control_obj['id'][2:]),title,md,control_category_obj['_id'])
                print('\tcreated')

        except Exception as e:
            print('error processing %s: %s'%(control_json_file_name,e))

    # Delete children of control doc in co
    exit(0)


if __name__ == '__main__':
    main()

