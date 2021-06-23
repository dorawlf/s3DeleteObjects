public class DeleteObjectsController {
 public static void deleteCallObjects(List<String> keysToDelete){
        
        String reqBody = generateXMLBody(keysToDelete);
        Blob reqBlobBody = Blob.valueOf(reqBody);
        Datetime reqTime = Datetime.now();
        Http h = new Http();
        
        // Instantiate a new HTTP request, specify the method (POST) as well as the endpoint
        HttpRequest req = new HttpRequest();
        req.setEndpoint('https://' + bucketName + '.s3.'+ AWSRegion +'.amazonaws.com/'+ '?delete');
        req.setMethod('POST');	
        
        headers.put('content-type','application/xml;charset=utf-8');//This is necessary!! Without this header, request body will be recognized as request string during authentication.
        headers.put('host', bucketName + '.s3.'+ AWSRegion +'.amazonaws.com');//This header is required for HTTP 1.1
        headers.put('content-md5', EncodingUtil.base64Encode(Crypto.generateDigest('MD5', reqBlobBody)));
        headers.put('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
        headers.put('x-amz-date', reqTime.formatGMT('yyyyMMdd\'T\'HHmmss\'Z\''));
        headers.put('content-length', String.valueOf(reqBlobBody.size()));
        for(String header:headers.keySet()){
            req.setHeader(header, headers.get(header));
        }
        System.debug('StringToSign:'+ GetStringToSign(reqTime,reqBlobBody));
        System.debug('SigningKey:' + CreateSigningKey(reqTime));
        req.setHeader(
            'Authorization', 
            String.format(
                'AWS4-HMAC-SHA256 Credential={0},SignedHeaders={1},Signature={2}',
                new String[] {
                    String.join(new String[] { AWSAccessKey, reqTime.formatGMT('yyyyMMdd'), AWSRegion, 's3', 'aws4_request' },'/'),
                        createSignedHeaders(),
                        EncodingUtil.convertToHex(Crypto.generateMac('hmacSHA256', Blob.valueOf(GetStringToSign(reqTime,reqBlobBody)), CreateSigningKey(reqTime)))}
            ));
        System.debug('Authorization:' + req.getHeader('Authorization'));
        
        req.setBodyAsBlob(reqBlobBody);
        HttpResponse res = h.send(req);
        if(res.getStatusCode()!= 200){
            throw new S3Exception('Fail to authorization。For details:' + res.getBody());
        }
    }
    
    private static String generateXMLBody(List<String> keysToDelete){
        String resultXML = '<?xml version="1.0" encoding="UTF-8"?>';
        resultXML += '<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
        
        for(String key:keysToDelete){
            resultXML += '<Object><Key>';
            resultXML += key;
            resultXML += '</Key></Object>';
        }
        
        //In quiet mode the response includes only keys where the delete action encountered an error. 
        //For a successful deletion, the action does not return any information about the delete in the response body.        
        resultXML += '<Quiet>false</Quiet>';
        resultXML += '</Delete>';
        
        return resultXML;
    }
    
    public class S3Exception extends Exception {}
    
    private static String GetStringToSign(Datetime reqTime, Blob reqBlobBody){
        System.debug('CreateCanonicalRequest');
        System.debug(CreateCanonicalRequest(reqBlobBody));
        return String.join(
            new String[] {
                'AWS4-HMAC-SHA256',
                    reqTime.formatGMT('yyyyMMdd\'T\'HHmmss\'Z\''),//TimeStamp ISO8601
                    String.join(new String[] { reqTime.formatGMT('yyyyMMdd'), AWSRegion, 's3', 'aws4_request' },'/'),//Scope<yyyyMMdd>/<aws_region>/s3/aws_request
                                EncodingUtil.convertToHex(Crypto.generateDigest('SHA-256', Blob.valueof(CreateCanonicalRequest(reqBlobBody))))
                    },
            '\n'
        );
    }
    
    private static Blob CreateSigningKey(Datetime reqTime){
        Blob result = Crypto.generateMac('hmacSHA256', Blob.valueOf('aws4_request'),
                                         Crypto.generateMac('hmacSHA256', Blob.valueOf('s3'),
                                                            Crypto.generateMac('hmacSHA256', Blob.valueOf(AWSRegion),
                                                                                   Crypto.generateMac('hmacSHA256', Blob.valueOf(reqTime.formatGMT('yyyyMMdd')), Blob.valueOf('AWS4' + AWSAccessSecretKey))
                                                                              )
                                                           )
                                        );
        return result;
    }
    
    private static String CreateCanonicalRequest(Blob reqBlodBody){
        
        Datetime callDate = Datetime.newInstanceGmt(2021, 1, 1);
        String year = callDate.format('yyyy');
        String month = callDate.format('MM');
        String day = callDate.format('dd');
        
        return String.join(
            new String[] {
                'POST',			//	METHOD
                    uriEncode('/',false),	//	RESOURCE
                    uriEncode('delete',true) + '=' + '',//	CANONICAL QUERY STRING
                    createCanonicalHeaders(),		//	CANONICAL HEADERS
                    createSignedHeaders(),			//	SIGNED HEADERS
                    'UNSIGNED-PAYLOAD'//	SHA256 PAYLOAD
                    },
            '\n'
        );
    }
    
    private static String createCanonicalHeaders(){
        String [] canonicalHeaders = new String [0];
        for(String header:headers.keySet()){
            canonicalHeaders.add(header.toLowerCase() + ':' + (headers.get(header)).trim());
        }
        canonicalHeaders.sort();
        return String.join(canonicalHeaders, '\n') + '\n';
    }
    
    private static String createSignedHeaders(){
        String [] signedHeaders = new String [0];
        for(String header:headers.keySet()){
            signedHeaders.add(header.toLowerCase());
        }
        signedHeaders.sort();
        return String.join(signedHeaders,';');
    }
    
    private static String uriEncode(String input, Boolean encodeSlash) {
        
        String result = '';
        
        for (Integer i = 0; i < input.length(); i++) {
            String ch = input.substring(i, i + 1);
            
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a'
                                             && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' ||
                ch == '-' || ch == '~' || ch == '.') {
                    result += ch;
                } else if (ch == '/') {
                    result += encodeSlash ? '%2F' : ch;
                } else {
                    String hexValue = EncodingUtil.convertToHex(Blob.valueOf(ch)).toUpperCase();
                    
                    if (hexValue.length() == 2) {
                        result += '%' + hexValue;
                    } else if (hexValue.length() == 4) {
                        result += '%' + hexValue.substring(0, 2) + '%' + hexValue.substring(2);
                    }
                }
        }
        return result;
    }
}
