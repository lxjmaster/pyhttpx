import pyhttpx

session = pyhttpx.HttpSession()
response = session.get("http://127.0.0.1:8888")
print(response.text)

