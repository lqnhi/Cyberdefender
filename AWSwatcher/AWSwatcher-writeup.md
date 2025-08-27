**AWS Watcher**   
\#1. During the initial scanning, the attacker interacted with the web application from an external IP address. What is the origin IP tied to the attacker, as observed in the AWS logs?

In AWS Lambda, click on FileUpload Function   
![](images/1.png)
There are 2 API Gateway Triggers and on the Description we could see the last modified section is 5 months ago on  2025-02-23T00:42:41.000Z   
Search for this specific day in CloudWatch \-\> Log Groups \-\> /aws/lambda/FileUpload  
Scroll down and we can see the log event: 2025/02/23/\[$LATEST\]18f1cb5f42e6497fa0260bfc1ebba47f   
![](images/2.png)
"X-Forwarded-For": "41.46.53.241",  
Answer: 41.46.53.241

\#2. A code review uncovered a function that lacked proper input validation, enabling arbitrary file processing. Which function’s misconfiguration directly enabled the initial exploit?

Open AWS dashboard, navigate to Lambda  
![](images/3.png)
  we can clearly see a function named FileUpload. Let's conduct a code review this function  
![](images/4.png)
This function is **file upload endpoint** via **API Gateway** that stores base64-encoded files into an **S3 bucket**. However, it did not validate filename input which is a significant security concern. It is highly likely that the FileUpload function is the root cause of the exploit.  
Answer: FileUpload

\#3. The attacker uploaded a file masquerading as a benign document but containing an embedded malicious payload. What’s the filename of the SVG payload disguised as a financial record?  
Open AWS S3, we previously identified “compliantsecurestoreddumpstorage” as the storage bucket for files uploaded through the FileUpload function   
![](images/5.png)  
Inside “compliantsecurestoreddumpstorage”, there is a folder named Upload.   
![](images/6.png)
Open it, inside we can see different file type, search for svg file extension  
![](images/7.png) 
Inside, we can see that it is likely financial\_statement\_2143.svg because of the file size

Answer: financial\_statement\_2143.svg

\#4. During analysis of the CloudWatch Logs, the attacker’s external IP address was observed invoking an API to upload files to an S3 bucket. What is the exact URL path used for this upload operation, as seen in the logs?

To answer this question, open CloudWatch Logs and filter the logs by the attacker's IP address to locate the exact URL path used for the file upload.  
![](images/8.png)

We can combine the protocol "https://" with "domainName": "[upilqcjrp5.execute-api.us-east-1.amazonaws.com](http://upilqcjrp5.execute-api.us-east-1.amazonaws.com)" and with the "path": "/prod/dev/upload"

Answer: https://[upilqcjrp5.execute-api.us-east-1.amazonaws.com](http://upilqcjrp5.execute-api.us-east-1.amazonaws.com)/prod/dev/upload

\#5. Which IAM role with excessive permissions was abused during the attack and used to query sensitive S3 buckets?  
CloudTrail Event History only shows the last 90 days by default.  
We you can still recover older activity if CloudTrail was set up to deliver logs to S3  
First go to Amazon S3 General purpose buckets, click on aws-cloudtrail-logs-149536493376-f6e00302   
![](images/9.png)  
click on AWSLogs/  
![](images/10.png)
Just continue and we can see the Cloudtrail   
![](images/11.png) 
As we are in the us-east-1, we choose us-east-1/   
![](images/12.png)
As in question 1, we know that the last modified section is 5 months ago on  2025-02-23T00:42:41.000Z   
so we choose 2025/ 02 / 23/

![](images/13.png) 
From here we sort the size of the file to see which log to choose from, We choose the larger file because it likely contains more data (e.g., full history or more detailed events).  
So we choose the first one with 79.5KB, click the file and then open.  
![](images/14.png)
As from question 2, we know that it has something to do with FileUpload, type Ctrl \+ F to search for /FileUpload   
![](images/15.png) 
Answer: LambdaParser

\#6. What is the MITRE ATT\&CK technique related to the attacker’s use of valid cloud credentials to log into the system?  
![](images/16.png) 
Answer: T1078.004

\#7. A server error inadvertently disclosed a temporary AWS access key in the debug logs. What is the AccessKeyId value that was leaked?  
![](images/17.png)
Just from question 6, we can also have the answer for accessKeyId: ASIASFUIRZ5AETONKITQ

\#8. A critical alert was triggered when the attacker invoked an API to retrieve temporary credentials. What is the Event ID of the GetRole API call?

\#9. Analysis of HTTP User-Agent strings and CLI artifacts suggests the attacker was using a penetration-testing operating system. Which operating system was likely used by the attacker?  
Based on the User-Agent strings and other artifacts, we can clearly see that the attacker was using Kali Linux.  
![](images/18.png)
"User-Agent": "Mozilla/5.0 (X11; Kali Linux x86\_64)

Answer: Kali
