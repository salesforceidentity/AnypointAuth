public class TokenResponse {
    
    public Integer statusCode {get;set;}
    public String access_token {get;set;}
    public String token_type {get;set;}
    public String redirectUrl {get;set;}
    
    public static TokenResponse processResponse(HttpResponse response) {
        
        if (response.getStatusCode() == 200) {
        	TokenResponse tr =  (TokenResponse) System.JSON.deserialize(response.getBody(), TokenResponse.class);
            tr.statusCode = response.getStatusCode();
            return tr;
        } else {
            TokenResponse tr = new TokenResponse();
            tr.statusCode = response.getStatusCode();
            return tr;
        }
        
    }
    
}