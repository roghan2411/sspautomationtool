from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify
from dotenv import load_dotenv
import os
import json
import re
from datetime import datetime
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.constants import OneLogin_Saml2_Constants
import uuid
import zlib
import base64
from urllib.parse import urlencode
import xml.etree.ElementTree as ET

# Completely bypass URL validation in the SAML library
def _patched_validate_url(url, allow_single_label_domain=False):
    """Bypass URL validation entirely"""
    return True

# Completely bypass all SAML validation
def _patched_check_settings(self, settings):
    """Bypass settings validation entirely"""
    return []

def _patched_check_idp_settings(self, settings):
    """Bypass IdP settings validation entirely"""
    return []

# Override core URL handling
def _patched_get_binding_type(self, url):
    """Always return HTTP-Redirect binding"""
    return OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT

# Override binding type at the transport level
def _patched_process_binding(self, request_data=None):
    """Force HTTP-Redirect binding for all requests"""
    return OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT

# Apply all patches
OneLogin_Saml2_Settings.validate_url = _patched_validate_url
OneLogin_Saml2_Settings.check_settings = _patched_check_settings
OneLogin_Saml2_Settings.check_idp_settings = _patched_check_idp_settings
OneLogin_Saml2_Auth.get_binding_type = _patched_get_binding_type
OneLogin_Saml2_Auth._process_binding = _patched_process_binding

# Custom SAML Settings class that handles bindings correctly
class CustomSAMLSettings(OneLogin_Saml2_Settings):
    def __init__(self, settings=None, custom_base_path=None, sp_validation_only=False):
        """Initialize settings without validation"""
        self._sp_validation_only = sp_validation_only
        self._paths = {}
        self._strict = False
        self._debug = True
        self._sp = {}
        self._idp = {}
        self._security = {}
        self._contacts = {}
        self._organization = {}
        self._errors = []

        if isinstance(settings, dict):
            self._sp = settings.get('sp', {})
            self._idp = settings.get('idp', {})
            self._strict = settings.get('strict', False)
            self._debug = settings.get('debug', True)
            self._security = settings.get('security', {})
            self._add_default_values()

    def get_idp_sso_url(self):
        """Always return the raw URL without validation"""
        return self._idp['singleSignOnService']['url']

    def _load_settings_from_dict(self, settings):
        """Load settings without any validation"""
        if isinstance(settings, dict):
            self._sp = settings.get('sp', {})
            self._idp = settings.get('idp', {})
            self._strict = settings.get('strict', False)
            self._debug = settings.get('debug', True)
            self._security = settings.get('security', {})
            self._add_default_values()
            return True
        return False

    def check_settings(self, settings):
        """Skip all settings validation"""
        return []

    def check_idp_settings(self, settings):
        """Skip IdP settings validation"""
        return []

    @staticmethod
    def validate_url(url, allow_single_label_domain=False):
        """Accept all URLs"""
        return True

app = Flask(__name__)
app.secret_key = os.urandom(24)
load_dotenv()

# File-based storage for SAML configurations
SAML_CONFIG_FILE = 'database/saml_configs.json'

def init_storage():
    os.makedirs('database', exist_ok=True)
    if not os.path.exists(SAML_CONFIG_FILE):
        with open(SAML_CONFIG_FILE, 'w') as f:
            json.dump([], f)

def load_saml_configs():
    with open(SAML_CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_saml_config(config):
    configs = load_saml_configs()
    if 'id' in config:
        # Update existing config
        for i, existing_config in enumerate(configs):
            if existing_config['id'] == config['id']:
                configs[i] = config
                break
    else:
        # New config
        config['id'] = str(len(configs) + 1)
        config['created_at'] = datetime.utcnow().isoformat()
        configs.append(config)
    
    with open(SAML_CONFIG_FILE, 'w') as f:
        json.dump(configs, f, indent=2)
    return config

def get_saml_config(config_id):
    configs = load_saml_configs()
    return next((c for c in configs if c['id'] == config_id), None)

def validate_acs_url(url):
    """Validate that the ACS URL matches our application's domain and paths"""
    from urllib.parse import urlparse
    parsed = urlparse(url.strip())
    
    # Check if URL is absolute
    if not parsed.scheme or not parsed.netloc:
        return False
        
    # The URL must use HTTPS (except for localhost or specific hostnames)
    if parsed.scheme != 'https' and not (
        parsed.netloc.startswith('localhost') or 
        parsed.netloc.startswith('roghan-') or
        parsed.netloc.startswith('trainee')
    ):
        return False
        
    # The path must start with /acs or /saml/acs
    if not (parsed.path.startswith('/acs') or parsed.path.startswith('/saml/acs')):
        return False
        
    return True

def is_valid_url(url):
    if not url:
        return False
    # Updated regex to handle domain names with hyphens
    regex = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'  # subdomains
        r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'  # domain name
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$'  # path
    )
    return bool(re.match(regex, url))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/saml')
def saml_options():
    return render_template('saml_options.html')

@app.route('/saml/config')
def saml_config():
    configs = load_saml_configs()
    return render_template('saml_config_list.html', configs=configs)

def generate_acs_urls(base_url, config_id, count):
    """Generate ACS URLs based on base URL, config ID and count"""
    urls = []
    base_url = base_url.rstrip('/')
    for i in range(1, count + 1):
        urls.append(f"{base_url}/{config_id}/acsurl{i}")
    return urls

@app.route('/saml/config/new', methods=['GET', 'POST'])
def saml_config_new():
    if request.method == 'POST':
        try:
            acs_url_count = int(request.form['acs_url_count'])
            base_url = request.form['base_url'].strip()
            
            if not base_url:
                flash('Base URL is required', 'error')
                return render_template('saml_config_new.html')
            
            if not acs_url_count or acs_url_count < 1 or acs_url_count > 5:
                flash('Please select a valid number of ACS URLs (1-5)', 'error')
                return render_template('saml_config_new.html')

            # Get next config ID for entity ID generation
            configs = load_saml_configs()
            next_id = str(len(configs) + 1)
            
            # Generate ACS URLs
            acs_urls = generate_acs_urls(base_url, next_id, acs_url_count)
            
            config = {
                'sp_name': request.form['sp_name'],
                'entity_id': f"{request.host_url.rstrip('/')}/saml/metadata/{next_id}",
                'acs_urls': acs_urls,
                'certificate': request.form['certificate'],
                'private_key': request.form['private_key'],
                'sign_requests': 'sign_requests' in request.form,
                'want_assertions_signed': 'want_assertions_signed' in request.form,
                'want_response_signed': 'want_response_signed' in request.form,
                'issuer_url': request.form['issuer_url'],
                'login_url': request.form['login_url'],
                'logout_url': request.form['logout_url']
            }
            
            save_saml_config(config)
            flash('SAML configuration saved successfully!', 'success')
            return redirect(url_for('saml_config'))
            
        except Exception as e:
            flash(f'Error creating configuration: {str(e)}', 'error')
            return render_template('saml_config_new.html')
        
    return render_template('saml_config_new.html')

@app.route('/saml/config/edit/<config_id>', methods=['GET', 'POST'])
def edit_saml_config(config_id):
    configs = load_saml_configs()
    config = next((c for c in configs if c['id'] == config_id), None)
    
    if config is None:
        flash('Configuration not found', 'error')
        return redirect(url_for('saml_config'))
    
    if request.method == 'POST':
        try:
            acs_url_count = int(request.form['acs_url_count'])
            base_url = request.form['base_url'].strip()
            
            if not base_url:
                flash('Base URL is required', 'error')
                return render_template('saml_config_edit.html', config=config)
            
            if not acs_url_count or acs_url_count < 1 or acs_url_count > 5:
                flash('Please select a valid number of ACS URLs (1-5)', 'error')
                return render_template('saml_config_edit.html', config=config)
            
            # Generate ACS URLs
            acs_urls = generate_acs_urls(base_url, config_id, acs_url_count)
            
            # Generate entity ID based on config ID and base URL
            entity_id = f"{request.host_url.rstrip('/')}/saml/metadata/{config_id}"
                
            # Update configuration with proper checkbox handling
            config.update({
                'sp_name': request.form['sp_name'],
                'entity_id': entity_id,  # Maintain auto-generated entity ID
                'acs_urls': acs_urls,
                'certificate': request.form['certificate'],
                'private_key': request.form['private_key'],
                'sign_requests': 'sign_requests' in request.form,
                'want_assertions_signed': 'want_assertions_signed' in request.form,
                'want_response_signed': 'want_response_signed' in request.form,
                'issuer_url': request.form['issuer_url'],
                'login_url': request.form['login_url'],
                'logout_url': request.form['logout_url']
            })
            
            save_saml_config(config)
            flash('Configuration updated successfully', 'success')
            return redirect(url_for('saml_config'))
            
        except Exception as e:
            flash(f'Error updating configuration: {str(e)}', 'error')
            return render_template('saml_config_edit.html', config=config)
    
    return render_template('saml_config_edit.html', config=config)

@app.route('/saml/config/<config_id>', methods=['GET'])
def get_saml_config_details(config_id):
    config = get_saml_config(config_id)
    if not config:
        app.logger.debug(f"Configuration with ID {config_id} not found.")
        return {"error": "Configuration not found"}, 404

    app.logger.debug(f"Returning configuration for ID {config_id}: {config}")
    return {
        "sp_name": config["sp_name"],
        "entity_id": config["entity_id"],
        "acs_urls": config["acs_urls"],
        "issuer_url": config["issuer_url"],
        "login_url": config["login_url"],
        "logout_url": config["logout_url"]
    }

@app.route('/saml/metadata/<sp_id>')
def saml_metadata(sp_id):
    config = get_saml_config(sp_id)
    if not config:
        return 'Configuration not found', 404
    
    # Build ACS service elements for each URL
    acs_services = '\n'.join(
        f'''        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                    Location="{url}"
                                    index="{index + 1}"/>''' 
        for index, url in enumerate(config['acs_urls'])
    )
    
    metadata = f'''<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                     validUntil="{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}"
                     entityID="{config['entity_id']}">
    <md:SPSSODescriptor AuthnRequestsSigned="{str(config['sign_requests']).lower()}" 
                        WantAssertionsSigned="{str(config['want_assertions_signed']).lower()}"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
{acs_services}
    </md:SPSSODescriptor>
</md:EntityDescriptor>'''
    
    return Response(metadata, mimetype='application/xml')

@app.route('/saml/metadata/<sp_id>/download')
def saml_metadata_download(sp_id):
    config = get_saml_config(sp_id)
    if not config:
        return 'Configuration not found', 404
    
    # Build ACS service elements for each URL
    acs_services = '\n'.join(
        f'''        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                    Location="{url}"
                                    index="{index + 1}"/>''' 
        for index, url in enumerate(config['acs_urls'])
    )
    
    metadata = f'''<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                     validUntil="{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}"
                     entityID="{config['entity_id']}">
    <md:SPSSODescriptor AuthnRequestsSigned="{str(config['sign_requests']).lower()}" 
                        WantAssertionsSigned="{str(config['want_assertions_signed']).lower()}"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
{acs_services}
    </md:SPSSODescriptor>
</md:EntityDescriptor>'''
    
    return Response(
        metadata,
        mimetype='application/xml',
        headers={'Content-Disposition': 'attachment; filename=metadata.xml'}
    )

@app.route('/saml/auth/list')
def saml_auth_list():
    configs = load_saml_configs()
    return render_template('saml_auth_list.html', configs=configs)

@app.route('/saml/auth/')
def saml_auth_fallback():
    return redirect(url_for('saml_auth_list'))

@app.route('/saml/auth/<config_id>')
def saml_auth(config_id):
    config = get_saml_config(config_id)
    if not config:
        flash('Configuration not found', 'error')
        return redirect(url_for('saml_auth_list'))

    return render_template('saml_auth.html', 
                         config_id=config_id,
                         acs_urls=config['acs_urls'])

@app.route('/saml/auth/<config_id>/generate', methods=['POST'])
def saml_auth_generate(config_id):
    try:
        config = get_saml_config(config_id)
        if not config:
            flash('Configuration not found', 'error')
            return redirect(url_for('saml_auth_list'))

        selected_acs_url = request.form.get('acs_url')
        if not selected_acs_url or selected_acs_url not in config['acs_urls']:
            flash('Invalid ACS URL selected', 'error')
            return redirect(url_for('saml_auth', config_id=config_id))

        # Generate SAML request manually
        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        request_id = '_' + str(uuid.uuid4())
        
        # Create SAML AuthnRequest directly
        saml_request = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{request_id}"
                    Version="2.0"
                    IssueInstant="{now}"
                    Destination="{config['login_url']}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    AssertionConsumerServiceURL="{selected_acs_url}">
    <saml:Issuer>{selected_acs_url}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                        AllowCreate="true"/>
</samlp:AuthnRequest>'''

        # Manually create the SAMLRequest parameter
        compressed_request = zlib.compress(saml_request.encode('utf-8'))[2:-4]
        b64_request = base64.b64encode(compressed_request).decode('utf-8')
        
        # Build the login URL manually
        params = urlencode({
            'SAMLRequest': b64_request,
            'RelayState': ''
        })
        login_url = f"{config['login_url']}{'&' if '?' in config['login_url'] else '?'}{params}"
        
        app.logger.debug(f"Generated SAML request: {saml_request}")
        app.logger.debug(f"Generated login URL: {login_url}")
        
        return render_template('saml_auth.html',
                            config_id=config_id,
                            acs_urls=config['acs_urls'],
                            saml_request=saml_request,
                            login_url=login_url)

    except Exception as e:
        app.logger.error(f"SAML Error: {str(e)}")
        flash(f"Error generating SAML request: {str(e)}", 'error')
        return render_template('saml_auth.html',
                            config_id=config_id,
                            acs_urls=config['acs_urls'])

@app.route('/saml/auth/send', methods=['POST'])
def saml_auth_send():
    saml_request = request.form['saml_request']
    # Here you would normally send this request to the IdP
    # For demo purposes, we'll just show the request
    return f'<pre>{saml_request}</pre>'

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    # Handle SAML response from IdP
    saml_response = request.form['SAMLResponse']
    decoded_response = base64.b64decode(saml_response).decode('utf-8')
    
    # Parse the SAML response XML
    from xml.etree import ElementTree as ET
    
    # Define namespaces
    namespaces = {
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
    }
    
    try:
        root = ET.fromstring(decoded_response)
        
        # Extract SAML data
        saml_data = {
            'issuer': '',
            'destination': root.get('Destination', ''),
            'in_response_to': root.get('InResponseTo', ''),
            'status': '',
            'name_id': '',
            'not_before': '',
            'not_on_or_after': '',
            'audience': '',
            'attributes': {}
        }
        
        # Get Issuer
        issuer = root.find('.//saml:Issuer', namespaces)
        if issuer is not None:
            saml_data['issuer'] = issuer.text
            
        # Get Status
        status = root.find('.//samlp:StatusCode', namespaces)
        if status is not None:
            saml_data['status'] = status.get('Value', '')
            
        # Find Assertion
        assertion = root.find('.//saml:Assertion', namespaces)
        if assertion is not None:
            # Get Subject/NameID
            name_id = assertion.find('.//saml:NameID', namespaces)
            if name_id is not None:
                saml_data['name_id'] = name_id.text
                
            # Get Conditions
            conditions = assertion.find('.//saml:Conditions', namespaces)
            if conditions is not None:
                saml_data['not_before'] = conditions.get('NotBefore', '')
                saml_data['not_on_or_after'] = conditions.get('NotOnOrAfter', '')
                
                # Get AudienceRestriction
                audience = conditions.find('.//saml:Audience', namespaces)
                if audience is not None:
                    saml_data['audience'] = audience.text
                    
            # Get Attributes
            attribute_statement = assertion.find('.//saml:AttributeStatement', namespaces)
            if attribute_statement is not None:
                for attribute in attribute_statement.findall('.//saml:Attribute', namespaces):
                    name = attribute.get('Name')
                    values = [value.text for value in attribute.findall('.//saml:AttributeValue', namespaces)]
                    saml_data['attributes'][name] = values
                    
    except ET.ParseError as e:
        app.logger.error(f"Failed to parse SAML response: {str(e)}")
        flash("Failed to parse SAML response", "error")
        saml_data = {}
        
    return render_template('saml_response.html', 
                         response=decoded_response,
                         saml_data=saml_data)

@app.route('/<config_id>/acsurl<index>', methods=['POST'])
def config_specific_acs(config_id, index):
    # Handle SAML response from IdP
    saml_response = request.form.get('SAMLResponse')
    if not saml_response:
        return 'No SAML response found', 400
        
    decoded_response = base64.b64decode(saml_response).decode('utf-8')
    
    # Parse the SAML response
    saml_data = {
        'status': '',
        'issuer': '',
        'destination': '',
        'in_response_to': '',
        'name_id': '',
        'not_before': '',
        'not_on_or_after': '',
        'audience': '',
        'attributes': {}
    }
    
    try:
        root = ET.fromstring(decoded_response)
        namespaces = {
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
        }
        
        # Get Status
        status = root.find('.//samlp:StatusCode', namespaces)
        if status is not None:
            saml_data['status'] = status.get('Value', '')
            
        # Get Response attributes
        saml_data['destination'] = root.get('Destination', '')
        
        # Get Issuer
        issuer = root.find('.//saml:Issuer', namespaces)
        if issuer is not None:
            saml_data['issuer'] = issuer.text
            
        # Get InResponseTo
        saml_data['in_response_to'] = root.get('InResponseTo', '')
        
        # Get Assertion
        assertion = root.find('.//saml:Assertion', namespaces)
        if assertion is not None:
            # Get NameID
            name_id = assertion.find('.//saml:NameID', namespaces)
            if name_id is not None:
                saml_data['name_id'] = name_id.text
                
            # Get Conditions
            conditions = assertion.find('.//saml:Conditions', namespaces)
            if conditions is not None:
                saml_data['not_before'] = conditions.get('NotBefore', '')
                saml_data['not_on_or_after'] = conditions.get('NotOnOrAfter', '')
                
                # Get AudienceRestriction
                audience = conditions.find('.//saml:Audience', namespaces)
                if audience is not None:
                    saml_data['audience'] = audience.text
                    
            # Get Attributes
            attribute_statement = assertion.find('.//saml:AttributeStatement', namespaces)
            if attribute_statement is not None:
                for attribute in attribute_statement.findall('.//saml:Attribute', namespaces):
                    name = attribute.get('Name')
                    values = [value.text for value in attribute.findall('.//saml:AttributeValue', namespaces)]
                    saml_data['attributes'][name] = values
                    
    except ET.ParseError as e:
        app.logger.error(f"Failed to parse SAML response: {str(e)}")
        flash("Failed to parse SAML response", "error")
        
    return render_template('saml_response.html', 
                         response=decoded_response,
                         saml_data=saml_data)

@app.route('/acs/<config_id>', methods=['POST'])
def config_specific_acs_handler(config_id):  # Renamed to avoid conflict
    saml_response = request.form.get('SAMLResponse', '')
    decoded_response = base64.b64decode(saml_response).decode('utf-8')
    
    # Parse SAML response
    root = ET.fromstring(decoded_response)
    ns = {'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    
    # Extract attributes
    saml_data = {}
    for attribute in root.findall('.//saml2:Attribute', ns):
        name = attribute.get('Name')
        values = [av.text for av in attribute.findall('saml2:AttributeValue', ns)]
        saml_data[name] = values[0] if len(values) == 1 else values

    return render_template('saml_response.html', response=decoded_response, saml_data=saml_data)

@app.route('/api/configure-urls', methods=['POST'])
def configure_urls():
    try:
        data = request.get_json()
        access_url = data.get('accessUrl', '').strip()
        config_id = data.get('configId')  # Get the config ID from the request
        
        if not access_url:
            return jsonify({'error': 'Access URL is required'}), 400
            
        # Parse the access URL
        from urllib.parse import urlparse, urljoin
        parsed_url = urlparse(access_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Get existing configuration
        config = None
        if config_id:
            config = get_saml_config(config_id)
            if not config:
                return jsonify({'error': 'Configuration not found'}), 404
        
        # Update URLs in the configuration
        updated_config = config or {}  # Use existing config or create new dict
        updated_config.update({
            'sp_name': updated_config.get('sp_name', f"SP {parsed_url.netloc}"),
            'entity_id': urljoin(base_url, '/saml/metadata'),
            'acs_urls': [
                urljoin(base_url, '/saml/acs'),
                urljoin(base_url, '/saml/acs/post')
            ],
            'issuer_url': urljoin(base_url, '/saml/metadata'),
            'login_url': urljoin(base_url, '/saml/login'),
            'logout_url': urljoin(base_url, '/saml/logout')
        })
        
        # Keep existing values for optional fields
        if config:
            # Preserve existing values that shouldn't change
            updated_config['certificate'] = config.get('certificate', '')
            updated_config['private_key'] = config.get('private_key', '')
            updated_config['sign_requests'] = config.get('sign_requests', False)
            updated_config['want_assertions_signed'] = config.get('want_assertions_signed', True)
            updated_config['want_response_signed'] = config.get('want_response_signed', True)
        
        # Save the configuration
        saved_config = save_saml_config(updated_config)
        
        return jsonify({
            'message': 'SAML URLs configured successfully',
            'config_id': saved_config['id']
        })
        
    except Exception as e:
        app.logger.error(f"Error configuring URLs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/saml-config/<config_id>', methods=['DELETE'])
def delete_config(config_id):
    try:
        config = get_saml_config(config_id)
        if not config:
            return jsonify({'error': 'Configuration not found'}), 404
            
        delete_saml_config(config_id)
        return jsonify({'message': 'Configuration deleted successfully'})
        
    except Exception as e:
        app.logger.error(f"Error deleting configuration: {str(e)}")
        return jsonify({'error': str(e)}), 500

def delete_saml_config(config_id):
    """Delete a SAML configuration by ID"""
    configs = load_saml_configs()
    configs = [c for c in configs if c['id'] != config_id]
    with open(SAML_CONFIG_FILE, 'w') as f:
        json.dump(configs, f, indent=2)

@app.after_request
def after_request(response):
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Set secure cookie attributes
    if 'Set-Cookie' in response.headers:
        response.headers['Set-Cookie'] = response.headers['Set-Cookie'].replace('HttpOnly', 'HttpOnly; Secure')
    
    return response

def create_saml_auth(request, config, selected_acs_url):
    """Helper function to create SAML auth object with proper settings"""
    # Build request info
    req = {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': str(request.environ.get('SERVER_PORT', '443')),
        'get_data': {},
        'post_data': {},
        'script_name': '',
        'server_name': request.host.split(':')[0] if ':' in request.host else request.host,
        'query_string': ''
    }

    # Minimal SAML settings
    saml_settings = {
        'sp': {
            'entityId': config['entity_id'],
            'assertionConsumerService': {
                'url': selected_acs_url,
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
            }
        },
        'idp': {
            'entityId': config['issuer_url'],
            'singleSignOnService': {
                'url': config['login_url'],
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            }
        },
        'security': {
            'nameIdEncrypted': False,
            'authnRequestsSigned': False,
            'logoutRequestSigned': False,
            'logoutResponseSigned': False,
            'signMetadata': False,
            'wantMessagesSigned': False,
            'wantAssertionsSigned': False,
            'requestedAuthnContext': False
        },
        'strict': False,
        'debug': True
    }

    return OneLogin_Saml2_Auth(req, saml_settings)

if __name__ == '__main__':
    init_storage()
    app.run(host='0.0.0.0', debug=True, ssl_context=('cert.pem', 'key.pem'))