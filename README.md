# Penetration_Testing1


Web App Pen Test Basics
Few of my learnings:

HTTP METHODS:
GET: GET method is used to Retrieve the Data. GET method Requests Server to Retrieve the Resource from specified URL. 
HEAD: HEAD method is similar to GET but, HEAD method Tells Server not to Send Actual Body of the message, Asks just Headers part. 
POST: POST method is used to Submit the Data to the specified resource. 
PUT: PUT method is used to replaces all current representations of the target resource with the request payload. 
OPTIONS: OPTIONS method is used to describe the allowed methods or communications options for the resource. 
DELETE: DELETE Request method Deletes the Specified Resource. 
CONNECT: CONNECT method is used for two way communications, it can be used to open the tunnel (Access Websites that use SSL (HTTPS)) 
TRACE: TRACE method gives a Message loopback. 
PATCH: PATCH method is used to make partial changes to the Resource.


HTTP RESPONSES : 
1xx- Informational Responses (100–199):
100 Continue: This response indicates that everything so far is OK and that the client should continue the Request. 
101 Switching Protocol:This code is sent in response to an Upgrade request header from the client, and indicates the protocol that server is switching to.
102 Processing (WebDAV):This code indicates that the server has received and is processing the request, but no response is available. 

2xx- Successful responses (200–299): 
200 OK:The request is Success. The meaning of this success depends on the HTTP method:GET: The resource has been fetched and transmitted the message body.HEAD: The entity headers are in the message body.PUT or POST: The resource describes the result transmitted is in the message body.TRACE: The message body contains the request message as received by the server.
201 Created:The request is success and a new resource has been created as a result. 
204 No Content:There is no content to send for this request, but the headers may be useful. 

3xx- Redirection messages (300-399):
301 Moved Permanently:The URL of the requested resource has been changed permanently. The new URL is given in the response.
302 Found:This response code means that the URI of requested resource has been changed temporarily. Further changes in the URI might be made in the future.
304 Not Modified:It tells the client that the response is not modified.
307 Temporary Redirect:The server sends this response to direct the client to get the requested resource at another URI with same method.
308 Permanent Redirect:This means that the resource is now permanently located at another URI. 

4xx- Client Error Responses (400-499):
400 Bad Request:The server could not understand the request due to invalid syntax.
401 Unauthorized:Although the HTTP Specifies "Unauthorized", this response means "unauthenticated". That is the client must authenticate itself to get the requested response.
403 Forbidden:The client does not have access or rights to give the content/resource requested. 
404 Not Found:The server can not find requested resource in the browser, which means the URL is not recognized.
405 Method Not Allowed:This requested method is known by the server but has been disabled and cannot be used.
407 Proxy Authentication Required:This is similar to 401 but authentication is needed to be done by a proxy.
409 Conflict:This response is sent when a request conflicts(DisAgree or Doesn't accept) with the current state of the server. 

5xx- Server Error Responses:
500 Internal Server Error:The server has encountered a situation that it doesn't know how to handle.
505 HTTP Version Not SupportedThe HTTP version used in the request is not supported by the server.
511 Network Authentication RequiredThe 511 status code indicates that the client needs to authenticate to gain network access.


REQUEST HEADERS	:
Accept:It informs the server about the types of data that can Accepted.
Accept-Charset:It tells what are the different character sets that are Acceptable.
Accept-Encoding:It tells about the Acceptable Encodings that are supported by the browser.
Accept-Language:It tells what are the different languages accepted by the server.
Authorization:It contains the credentials to authenticate the user with the server.
Cache-control:It tells the proxy to cache the content or not,in both Request and Response headers.
Connection:It is the way of telling the client from server to continue(keep) the connection or close.
Cookies:Cookies are nothing but the flat files that stores the session information.
Content-Type:It Indicates the media type of the resource(request body).
Content-Length:It tells the server that what is the length/size of the Content sent, in number of bytes.
Date:This header contains the date and time at which the message was originated.
Host:It specifies the domain name of the server (for virtual hosting) to which the client is communicated to.
If-Modified-Since:It tells the server that OK, I have the object with me, serve me the object if modified since this particular time.
If-Unmodified-Since:It is similar to If-Modified-Since but, it only sends the object if not modified since time.
If-Match:In this header, For GET and HEAD methods, the server will send back the requested resource only if it matches with one of the ETags. For PUT and other non-safe methods, it will only upload the resource in this case.
If-None-Match:Similar to If-Match but here if it doesnot match with ETags it is If-None.Pragma:Pragma HTTP/1.0 general header is an implementation-specific header that may have various effects along the request/response.Range:from HTTP/1.1 onwards the server started supporting the byte range requests.
User-Agent:It lets server to identify the browser, operating system, software, and version of the requesting user agent.Via:It tells the server it comes from different proxies, Via is Important because it infroms servers it is not coming directly.X-Forwarded-For:This is an email-header indicating that an email-message was forwarded from another account.X-Forwarded-Host:This header is used for identifying the original host requested by the client in the Host HTTP request header.
Response Headers	Access-Control-Allow-Origin:it specifies which websites can participate in the cross origin resource sharing, it also tells what all contents of the website should be accepted.Accept-Ranges:It defines what kind of ranges it accepts, like bytes.Age:It tells about the Age of the object i.e., how long the object was cached in the proxy serverAllow:it tells what are the different HTTP methods that are allowed like GET,HEAD... Content-Disposition:it tells the browser not to load the content just download instead.Content-Encoding:It is used to encode or compress the media type .Content-Language:It tells the client what is the language of the content being served.Content-Length:it tells the length of the response bodyContent-Type:It tells about what is the MIME type of the contentDate:similar to request header, just tells the Date and time originatedETag:it tells the value of the content and used for mathing with help of If-Match & If-None-Match.Expires:it tells the proxy server or web browser when this response is going to expire.Last-Modified:it tells what was the last modified time of the object on the server side.Location:it is served when there is any redirect 301 or 302 from the server side and also mentions actual resource or new loactionRetry-After:It tells the client if the entity is not available on the client then retry after particular mentioned time.Server:similar to the User-Agent, it is the identity of the Server.(what server is being used).Set-Cookie:it is used to send cookies from the server to the user agent, so the user agent can send them back to the server later.Tranfer-Encoding:it is the form of encoding used to safely Tranfer the data it may be chunked response.Vary:it tells how to match future request headers to decide whether the cached response can be used rather than requesting new one from origin server.WWW-Authenticate:this response header defines the authentication method that should be used to gain access to a resource.Strict-Transport-Security:it lets a web site tell browsers that it should only be accessed using HTTPS, instead of using HTTP.

Encoding,Encryption,Hashing	Encoding, Encryption and Hashing are techniques used for converting the format of data. These methods are used in various levels of security to data that has been transformed. 

Encoding - Encoding is used for changing the data into a special format which makes it usable by external processes.encoding is just a technique to transform data into other formats so that it can be consumed by numerous systems. There is no use of keys in encoding.The algorithm that is used to encode the data is used to decode it as well. ASCII and UNICODE are examples of such algorithms. 

Encryption - Encryption is used for changing plain text into cipher text so that only authorized entities can understand it.It is the process of transforming your confidential data into an unreadable format so that no hacker or attacker can manipulate or steal it. Thereby, serving the purpose of confidentiality.encryption trades with keys which are used to encrypt and decrypt the data. These keys are used to change a simple text into a cypher text .Encryption is used to Security of dataSymmetric Encryption: In symmetric encryption, the data is encrypted and decrypted using a single cryptographic key. It means that the key used for encryption is used for decryption as well.Asymmetric Encryption: Asymmetric encryption use two different keys, one for encryption and one for decryption purposes. One key is known as a ‘Public Key’ and the other is a ‘Private Key.’ 

Hashing - In Hashing the data is converted to a message digest or hash, which is usually a number generated from a string of text. Hashing is not reversible as encryption and encoding.Hashing is used to Verification of data. It is used in Digital signatures and SSL certificates
HTTP Secure Headers	Content Security Policy:(CSP):Content Security Policy response header prevent cross-site scripting attack or code injection attack by denying the execution of malicious contents from untrusted sites. CSP header instructthe browser from which location and which type of resources are allowed to be loaded."Content-Security-Policy" content="default-src.X-XSS-Protection:X-XSS-Protection response header is designed to protect the application from cross site scripting. Header will instruct the browser to enable the cross site scripting filter which are builtin modern web browsers like chrome and Firefox.X-XSS-Protection: 1; mode=blockX-Frame-Options:X-Frame-Options response header is designed to protect the application from clickjacking or UI redressing.Header will instruct the browser not to embed web pages in iframe options.X-Frame-Options: SAMEORIGINX-Content-Type-Options:X-Content-Type-Options response header is designed to protect the application against MIME sniffing attack. Header will instruct the browser that content-type should not be changed and be followed.X-Content-Type-Options: nosniff.Access-Control-Allow-Origin:Access-Control-Allow-Origin response header deals with resource sharing. Header will instruct the browser whether the response can be shared or not.Access-Control-Allow-Origin: http://www.origin.com.Strict-Transport-Security:Strict-Transport-Security response header prevent web browser from accessing webs in stateless HTTPconnections. Header will instruct the browser to access web pages using HTTPS, instead of using HTTP.Strict-Transport-Security: max-age=31536000; includeSubDomainsPublic-Key-PinsPublic-Key-Pins response header prevent web browser from MITM attacks using rogue and forged certificates. Header will instruct the browser to associate/save a specific cert public key, which helps browser which certificate to trust.
CORS & Same-origin policy	Cross Origin Resource Sharing (CORS)CORS (Cross-Origin Resource Sharing) is a mechanism by which data or any other resource of a site could be shared intentionally to a third party website when there is a need. Generally, access to resources that are residing in a third party site is restricted by the browser clients for security purposes.Same-origin policy:The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain. The same-origin policy was defined many years ago in response to potentially malicious cross-domain interactions, such as one website stealing private data from another. It generally allows a domain to issue requests to other domains, but not to access the responses.
S3 Bucket	Amazon Simple Storage Service is storage for the Internet. It is designed to make web-scale computing easier for developers.Amazon S3 has a simple web services interface that you can use to store and retrieve any amount of data, at any time, from anywhere on the web.It gives any developer access to the same highly scalable, reliable, fast, inexpensive data storage infrastructure that Amazon uses to run its own global network of web sites. The service aims to maximize benefits of scale and to pass those benefits on to developers.
UnRestricted File Uploads	This script is possibly vulnerable to unrestricted file upload. Various web applications allow users to upload files (such as pictures, images, sounds, ...). Uploaded files may pose a significant risk if not handled correctly. A remote attacker could send a multipart/form-data POST request with a specially-crafted filename or mime type and execute arbitrary code.
Unrestricted File Uploads	In any server we can upload any kind of files only when:1.Upload Functonality 2.Put Method Enable.If Upload Functionality is Available , in place of any Upload type we have to give the Shell File to Uploadexample: In place of Upload Image, We give our Shell File in this case.Based on the Server's Backend Technology, We give our Shell File Type either PHP,ASP,JSPExample: If Servers Backend is PHP, Shell is PHP ShellPUT Method Enable or PUT method Exploitation is the other type where we check whether the Put method is accepted or not.OPTIONS method is used to check if PUT is accepted or not.
Sql map	Checking for Sql injection if possible or not through BurpScan and checking the parameter whereSql Injection can be performed (Eg:Referer,Id=?) and then sqlmap testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. command: 1.) sqlmap -u "https://target.com/index.php?name=abc*&lastname=def". or. sqlmap -u "https://target.com/index.php?name=abc" --risk=3 --level=5 2.) sqlmap -r /file.txt -p "def" --dbs --threads 5 Eg:( sqlmap -r foophones.txt -p "Referer" --risk=3 --level=3 --dbs ) (save file into abcd.txt and save it on Desktop) cd Desktop==>sqlmap -r foophones.txt -p "Referer" --risk=3 --level=3 --dbs
Broken Access Control

Access Control:
Access control (or authorization) is the application of Limitations or Restrictions on who (or what) can perform actions or access the resources that they have requested. In the context of web applications, access control is dependent on authentication and session management

Authentication: It identifies the user and confirms that they are who they say they are.(Obtaining our profile by submitting the login credentials to prove our identity is called Authentication).
Session management: It identifies which subsequent HTTP requests are being made by that same user.
Access control: It determines whether the user is allowed to carry out the action that they are attempting to perform.
Broken access controls are a commonly encountered and often critical security vulnerability. Design and management of access controls is a complex. Access control design decisions have to be made by humans, not technology, and the potential for errors is high.
From a user perspective, access controls can be divided into the following categories:

[Vertical access controls](https://portswigger.net/web-security/access-control#vertical-access-controls) 			
        [Horizontal access controls](https://portswigger.net/web-security/access-control#horizontal-access-controls) 			
[Context-dependent access controls](https://portswigger.net/web-security/access-control#context-dependent-access-controls) 			
Vertical access controls
Vertical access controls are mechanisms that restrict access to sensitive functionality that is not available to other types of users.
With vertical access controls, different types of users have access to different application functions. For example, an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions.

Horizontal access controls
Horizontal access controls are mechanisms that restrict access to resources to the users who are specifically allowed to access those resources.
With horizontal access controls, different users have access to a subset of resources of the same type. For example, a banking application will allow a user to view transactions and make payments from their own accounts, but not the accounts of any other user.

Context-dependent access controls
Context-dependent access controls restrict access to functionality and resources based upon the state of the application or the user's interaction with it.
Context-dependent access controls prevent user performing actions in the wrong order. For example, a retail website might prevent users from modifying the contents of their shopping cart after they have made payment.

Examples of broken access controls
Broken access control vulnerabilities exist when a user can, in fact, access some resource or perform some action that they are not supposed to be able to access.

Vertical privilege escalation
If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. For example, if a non-administrative user can in fact gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.

Access Control:
Access control (or authorization) is the application of Limitations or Restrictions on who (or what) can perform actions or access the resources that they have requested. In the context of web applications, access control is dependent on authentication and session management

Authentication: It identifies the user and confirms that they are who they say they are.(Obtaining our profile by submitting the login credentials to prove our identity is called Authentication).
Session management: It identifies which subsequent HTTP requests are being made by that same user.
Access control: It determines whether the user is allowed to carry out the action that they are attempting to perform.
Broken access controls are a commonly encountered and often critical security vulnerability. Design and management of access controls is a complex. Access control design decisions have to be made by humans, not technology, and the potential for errors is high.
From a user perspective, access controls can be divided into the following categories:

[Vertical access controls](https://portswigger.net/web-security/access-control#vertical-access-controls) 			
        [Horizontal access controls](https://portswigger.net/web-security/access-control#horizontal-access-controls) 			
[Context-dependent access controls](https://portswigger.net/web-security/access-control#context-dependent-access-controls) 			
Vertical access controls
Vertical access controls are mechanisms that restrict access to sensitive functionality that is not available to other types of users.
With vertical access controls, different types of users have access to different application functions. For example, an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions.

Horizontal access controls
Horizontal access controls are mechanisms that restrict access to resources to the users who are specifically allowed to access those resources.
With horizontal access controls, different users have access to a subset of resources of the same type. For example, a banking application will allow a user to view transactions and make payments from their own accounts, but not the accounts of any other user.

Context-dependent access controls
Context-dependent access controls restrict access to functionality and resources based upon the state of the application or the user's interaction with it.
Context-dependent access controls prevent user performing actions in the wrong order. For example, a retail website might prevent users from modifying the contents of their shopping cart after they have made payment.

Examples of broken access controls
Broken access control vulnerabilities exist when a user can, in fact, access some resource or perform some action that they are not supposed to be able to access.

Vertical privilege escalation
If a user can gain access to functionality that they are not permitted to access then this is vertical privilege escalation. For example, if a non-administrative user can in fact gain access to an admin page where they can delete user accounts, then this is vertical privilege escalation.
