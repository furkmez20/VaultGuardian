# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Length

class MFAForm(FlaskForm):
    otp_code = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])
