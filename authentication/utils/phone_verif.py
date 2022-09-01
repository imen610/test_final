from twilio.rest import Client

def send_verification(to, otp):
    account_sid = "AC555b8b1b6867a8980ad281a63cc184ff"
    auth_token = "50c5b7c33da74d1e7bc201c30558bc8b"
    client = Client(account_sid, auth_token)

    client.messages.create(
        body=f"Your FirePay Wallet Verification code is {otp}, DO NOT share with Anyone!",
        from_='+19289625777',
        to=to
    )
