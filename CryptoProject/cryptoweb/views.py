from django.shortcuts import render, HttpResponse, redirect
from Crypto.Util.number import *
from Crypto.Cipher import AES, DES
import base64
from hashlib import *

# Create your views here.

symmetric_crypt = ["AES", "DES", "RC4", "BASE64"]
asymmetric_crypt = ["RSA"]
hash_method = ["md5", "SHA1", "SHA2"]


class SC_OPTIONS():
	def __init__(self, form_values):
		self.__form_values = form_values

	def __get_algm(self):
		try:
			# print("algm: ".format(self.__form_values["algm"]))
			# return symmetric_crypt.index(self.__form_values["algm"])
			return self.__form_values["algm"]
		except:
			return False

	def __aes_ops(self):
		# encrypt
		if self.__form_values["options"] == "1":
			plain_text = self.__form_values["input_text"].encode()
			key = self.__form_values["key"].encode()
			iv = self.__form_values["iv"].encode()
			aes = AES.new(key, AES.MODE_CBC, iv)
			crypted_text = aes.encrypt(plain_text)

			return str(bytes_to_long(crypted_text))
		# decrypt
		else:
			pass

	def __des_ops(self):
		pass

	def __base64_ops(self):
		if self.__form_values["options"] == "1":
			plain_text = self.__form_values["input_text"].encode()
			res = base64.b64encode(plain_text)
			return res.decode()

	def options(self):
		algm = self.__get_algm()
		if not algm:
			print("not such encrypt/encode method")
		if algm == "AES":
			return self.__aes_ops()
		elif algm == "DES":
			return self.__des_ops()
		elif algm == "BASE64":
			return self.__base64_ops()


class HASH_OPTIONS():
	def __init__(self, form_value):
		  self.__form_value = form_value

	def __hash_ops(self):
		plain_text = self.__form_value["input_text"]
		hl = md5()
		hl.update(plain_text.encode("utf-8"))
		crypto_text = str(bytes_to_long(hl.digest()))
		return crypto_text


	def options(self):
		algm = self.__form_value["algm"]
		if algm == "md5":
			return self.__hash_ops()



def home_page(request):
	return render(request, "cryptoweb/homepage.html")


def symmetric_encrypt(request):
	if request.method == "GET":
		return render(request, "cryptoweb/symmetric_crypt.html", {"method_list": symmetric_crypt})

	algm = request.POST.get("algm")
	ops = request.POST.get("ops")
	input_text = request.POST.get("input_text")
	key = request.POST.get("key")
	iv = request.POST.get("iv")

	form_values = {"algm": algm, "options": ops, "input_text": input_text, "key": key, "iv": iv}

	print("parameters: {}, {}, {}, {}".format(algm, ops, input_text, key))
	sc = SC_OPTIONS(form_values)
	res = sc.options()

	return render(request, "cryptoweb/symmetric_crypt.html",
	              {"method_list": symmetric_crypt, "output": res, "form": form_values})


def asymmetric_encrypt(request):
	return render(request, "cryptoweb/asymmetric_encrypt.html", {"method_list": asymmetric_crypt})


def hash_calc(request):
	if request.method == "GET":
		return render(request, "cryptoweb/hash.html", {"hash_method": hash_method})
	algm = request.POST.get("hash_algm")
	input_text = request.POST.get("input_text")

	form_values = {"algm": algm, "input_text": input_text}

	ho = HASH_OPTIONS(form_values)
	res = ho.options()

	return render(request, "cryptoweb/hash.html", {"hash_method": hash_method, "output": res, "form": form_values})


