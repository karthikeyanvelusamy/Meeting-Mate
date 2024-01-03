import traceback

from flask import Flask, redirect, url_for, session, request, json
from authlib.integrations.flask_client import OAuth
import os
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv
from googleapiclient.discovery import build
from datetime import datetime
from flask import Flask, render_template, session
from flask_session import Session
import base64
from email.mime.text import MIMEText
from datetime import datetime
import pytz


load_dotenv()
app = Flask(__name__)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_secret_key')
service= None

app.config['SESSION_TYPE'] = 'filesystem'
Session(app)


oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'https://www.googleapis.com/auth/gmail.send ' +
                 'https://www.googleapis.com/auth/calendar ' +
                 'email profile ' +
                 'https://www.googleapis.com/auth/userinfo.email ' +
                 'https://www.googleapis.com/auth/userinfo.profile',
        'token_endpoint_auth_method': 'client_secret_post',
        'token_placement': 'header',
        'redirect_uri': 'http://localhost:5000/authorize',
        'access_type': 'offline'
    }
)

@app.route('/')
def index():

    data = { 'logged_in' : 'token' in session,
             'user_info' :  session['user_info'] if 'user_info' in session else None,
             'cal_meetings': session['cal_meetings'] if 'cal_meetings' in session else None}

    if data['logged_in']:

        return render_template("cal_view2.html",data=data)

    return render_template('index4.html', data=data)


@app.route('/login')
def login():
    return google.authorize_redirect()

@app.route('/authorize')
def authorize():

    token = google.authorize_access_token()

    print("Token ***** "+ str(token))
    session['token'] = token

    session['user_info'] = google.get('userinfo').json()
    print("User Info " + str(session['user_info']))

    credentials = Credentials(
        token=token.get('access_token'),
        refresh_token=None,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=os.environ.get('GOOGLE_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    )

    cal_service = build('calendar', 'v3', credentials=credentials)
    gmail_service = build('gmail', 'v1', credentials=credentials)

    session['calender_service'] = cal_service
    session['gmail_service'] = gmail_service
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/fetch', methods = ['POST'])
def fetch_meetings():
    service = session['calender_service']
    if service:
        print(session['token'])

        future_date = request.form['future_date']

        future_date_obj = datetime.strptime(future_date, '%Y-%m-%d')
        futureDateTime = future_date_obj.isoformat() + 'Z'
        try:
            timenow = datetime.utcnow().isoformat()+ 'Z'

            events_result = service.events().list(
                calendarId='primary',
                timeMin=timenow,
                timeMax=futureDateTime,
                singleEvents=True,
                orderBy='startTime'
            ).execute()

            events = events_result.get('items', [])



            one_on_one_events = get_events_processed(events)

            session['cal_meetings']  =one_on_one_events
            return redirect(url_for('index'))

        except Exception as e:
            traceback.print_exc()
            return f'An error occurred: {e}'
    else:
        return 'User not logged in or token not found in session'


@app.route('/send_reminder' , methods=['POST'])
def send_reminder():
    request_body = request.data
    request_body =  json.loads(request_body.decode('utf-8'))  # Decode and load JSON data
    service = session['gmail_service']
    sender_email =   session['user_info']['email']
    sender_name = "Meeting Mate"
    sender = f'"{sender_name}" <{sender_email}>'
    recipients = request_body['recipients']
    message = request_body['message']
    response_data = []
    for recipient in recipients:
       response_data.append(send_message(service, create_message(sender, recipient['email'],
                                            "Reminder for " +  recipient['summary'],message)))

    print(response_data)

    return response_data

def create_message(sender, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    print("message : "+ str(message))
    return {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode()}

def send_message(service, message):
    try:
        message = service.users().messages().send(userId='me', body=message).execute()
        print('Message Id: %s' % message['id'])
        return message
    except Exception as e:
        print('An error occurred: %s' % e)

def get_events_processed(events):
    result = []
    for event in events:
        if 'attendees' in event and len(event['attendees']) == 2:
            print(event)
            data = {
                'id': event['id'],
                'summary': event['summary'],
                'htmlLink': event['htmlLink'],
                'start': convert_time(event['start']['dateTime'], event['start'].get('timeZone')),
                'end': convert_time(event['end']['dateTime'], event['end'].get('timeZone')),
                'attendee': [e['email'] for e in event.get('attendees', []) if not e.get('self', False)][0]
            }
            result.append(data)

    return result


def convert_time(date_time_str, timezone):
    original_dt = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M:%S%z')

    pst_tz = pytz.timezone(timezone)

    pst_dt = original_dt.astimezone(pst_tz)

    return pst_dt.strftime('%Y-%m-%d %I:%M %p %Z')


if __name__ == '__main__':
    app.run(debug=True)
