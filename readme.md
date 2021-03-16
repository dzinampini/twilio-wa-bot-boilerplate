# Setup twillio
Tutorial from https://www.twilio.com/docs/whatsapp/quickstart/python

## Get a number 

## get Twillio credentials
https://www.twilio.com/console

Acocunt SID:
AC697fc91963a9d3f554f2371efde90f26

Auth token:
eac9c84967a821d4c8a6b7b1f5cac0f2

## Run python project 

## Run python project on ngrok

### package install
```py
>pip install -r requirements.txt
```

### run app
set flask app 
```sh
# windows
>set FLASK_APP=tomcat
# linux
>export FLASK_APP=tomcat
```

then
```sh
>flask run
```

### also fire up on ngrok
download ngrok first - https://ngrok.com/download

- make sure your project is running 

- fire command ngrok http 5000

- use first ngrok link 

## might need
# range climate og API link
https://channels.autopilot.twilio.com/v1/AC697fc91963a9d3f554f2371efde90f26/UAcbead929532c36d6d262b82edc8abe89/twilio-messaging/whatsapp

whatsapp:+15005550006

## Accessing sandbox
https://www.twilio.com/console/sms/whatsapp/sandbox

http://3ab3fd36705c.ngrok.io/tomcat
http://a618f00d19a0.ngrok.io