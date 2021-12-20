# Setup twillio
Tutorial from https://www.twilio.com/docs/whatsapp/quickstart/python

## get Twillio credentials
https://www.twilio.com/console

The credentials are:
1. Acocunt SID
2. Auth token

## Run python project 

### package install (first time only)
```py
>pip install -r requirements.txt
```

### actually running 
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
Twilio whatsapp number: +15005550006

Accessing sandbox link: https://www.twilio.com/console/sms/whatsapp/sandbox
