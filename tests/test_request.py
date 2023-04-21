import pyhttpx

session = pyhttpx.HttpSession()
response = session.get("https://localhost:8443")
print(response.text)

