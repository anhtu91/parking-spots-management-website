import requests

ip_address_tile38 = '172.18.0.4'
port_tile38 = '9851'


r = requests.get('http://'+ip_address_tile38+':'+port_tile38+'/KEYS *')

print(r.status_code)
print(r.json())

data = r.json()

ok = data['ok']

print(ok)

keyID = data['keys']

print(keyID)