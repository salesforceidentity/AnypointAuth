/*
 * Implements Authentication Options found at  
 * https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/access-management-api/api/v1/pages/Authentication/
 * 
 */
public class AnypointAuth {
    
    private static String USERNAME_ENDPOINT = 'https://anypoint.mulesoft.com/accounts/login';
    private static String SAML_ENDPOINT = 'https://anypoint.mulesoft.com/accounts/login/receive-id';
    private static String APP_JSON = 'application/json';
    private static String X_REQUESTED_WITH = 'XMLHttpRequest';
    private static String METHOD = 'POST';
    
    
        
    public TokenResponse exchangeUsernamePassword(String username, String password) {
        
        JSONGenerator gen = JSON.createGenerator(true);    
        gen.writeStartObject();      
        gen.writeStringField('username', username);
        gen.writeStringField('password', password);
        gen.writeEndObject();   
        
        HttpRequest request = new HttpRequest();
        request.setEndpoint(USERNAME_ENDPOINT);
        request.setHeader('Content-Type', APP_JSON);
        request.setHeader('Accept', APP_JSON);
        request.setMethod(METHOD);
        request.setBody(gen.getAsString());
        
        Http http = new Http();
        HTTPResponse response = http.send(request);
        return TokenResponse.processResponse(response);
        
    }
    
    public TokenResponse exchangeSAMLAssertion(String username, String issuer, String idpCert, String spEntityId, String acsUrl) {
        
        String samlResponse = getSAMLResponse(username, issuer, idpCert, spEntityId, acsUrl);

        JSONGenerator gen = JSON.createGenerator(true);    
        gen.writeStartObject();      
        gen.writeStringField('SAMLResponse', samlResponse);
        gen.writeEndObject();   
        
        HttpRequest request = new HttpRequest();
        request.setEndpoint(SAML_ENDPOINT);
        request.setHeader('Content-Type', APP_JSON);
        request.setHeader('Accept', APP_JSON);
        request.setHeader('X-Requested-With', X_REQUESTED_WITH);
        request.setMethod(METHOD);
        System.debug(gen.getAsString());
       	request.setBody(gen.getAsString());
        
        Http http = new Http();
        HTTPResponse response = http.send(request);
        return TokenResponse.processResponse(response);
        
    }
    
    private String getSAMLResponse(String subject, String issuer, String idpCert, String spEntityId, String acsUrl) {
        DateTime myDateTime = DateTime.now();
        String UTC = myDateTime.formatGmt('yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\'');

        Dom.Document Response_DOM = new Dom.Document();
        DOM.XmlNode Root_Response = Response_DOM.createRootElement('Response', 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp');
        //InResponseTo is not set with unsolicited SAML
        //Root_Response.setAttribute('InResponseTo', this.AssertionId);
        Root_Response.setAttribute('Version', '2.0');
        Root_Response.setAttribute('IssueInstant', UTC);
        Root_Response.setAttribute('Destination', acsURL);
        DOM.XmlNode Element;
        Element = Root_Response.addChildElement('Issuer', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');   
        Element.setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity');
        Element.addTextNode(issuer);
        DOM.XmlNode status_Element = Root_Response.addChildElement('Status','urn:oasis:names:tc:SAML:2.0:protocol','samlp');
        Element = status_Element.addChildElement('StatusCode','urn:oasis:names:tc:SAML:2.0:protocol','samlp');
        Element.setAttribute('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success');
        DOM.XmlNode Element_Assertion = Root_Response.addChildElement('Assertion','urn:oasis:names:tc:SAML:2.0:assertion','saml');
        Element_Assertion.setAttribute('IssueInstant', UTC);
        Element_Assertion.setAttribute('Version', '2.0');
        Element = Element_Assertion.addChildElement('Issuer', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');   
        Element.setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity');
        Element.addTextNode(issuer);
        DOM.XmlNode Element_Subject = Element_Assertion.addChildElement('Subject', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element = Element_Subject.addChildElement('NameID', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element.setAttribute('Format','urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
        Element.addTextNode(subject);
        Element = Element_Subject.addChildElement('SubjectConfirmation', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element.setAttribute('Method','urn:oasis:names:tc:SAML:2.0:cm:bearer');
        Element = Element.addChildElement('SubjectConfirmationData', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element.setAttribute('NotOnOrAfter', myDateTime.addMinutes(5).formatGmt('yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\''));
        Element.setAttribute('Recipient', acsUrl); 
        
        Element = Element_Assertion.addChildElement('Conditions','urn:oasis:names:tc:SAML:2.0:assertion','saml');
        Element.setAttribute('NotOnOrAfter', myDateTime.addMinutes(5).formatGmt('yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\''));
        Element.setAttribute('NotBefore', UTC);
        DOM.XmlNode Element_AudienceRestriction = Element.addChildElement('AudienceRestriction', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element = Element_AudienceRestriction.addChildElement('Audience', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element.addTextNode(spEntityId);
        
        Element = Element_Assertion.addChildElement('AuthnStatement','urn:oasis:names:tc:SAML:2.0:assertion','saml');
        Element.setAttribute('AuthnInstant', DateTime.now().formatGmt('yyyy-MM-dd\'T\'HH:mm:ss.SSS\'Z\''));
        Element = Element.addChildElement('AuthnContext', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element = Element.addChildElement('AuthnContextClassRef', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element.addTextNode('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified');
       
        
        Element = Element_Assertion.addChildElement('AttributeStatement', 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml');
        Element = Element.addChildElement('Attribute','urn:oasis:names:tc:SAML:2.0:assertion','saml');
        Element.setAttribute('Name', 'email');
        Element.setAttribute('NameFormat','urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified');
        Element = Element.addChildElement('AttributeValue','urn:oasis:names:tc:SAML:2.0:assertion','saml');
        Element.addTextNode(subject);           
		
        Crypto.signXml('RSA-SHA1', Element_Assertion, NULL, idpCert, Element_Subject);
        Crypto.signXml('RSA-SHA1', Root_Response, NULL , idpCert, status_Element);
        return EncodingUtil.base64Encode(Blob.valueOf(Response_DOM.toXmlString()));
    }
        
}