import jwt
import qrcode
import PIL
import configparser
import os

config = configparser.ConfigParser()

config.read(os.path.dirname(os.path.abspath(__file__))+'/config.conf')
private_key = config.get('JWT', 'private_key')

encoded = jwt.encode({"Location":"abc123","url":"data","nothing":"2333","aud":"client","azp":"hihihihi","tokenType":"123456"}, private_key, algorithm="RS512")

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(encoded)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
iml = img.save(os.path.dirname(os.path.abspath(__file__))+"/invite_qr_code/testqrjwt.png")
