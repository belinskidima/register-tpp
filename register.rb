require 'openssl'
require 'securerandom'
require 'jwt'
require 'json'
require 'rest-client'
require_relative './signature_helper'

#########################################
# ---------- CONFIGURATION --------------
CLIENT_EMAIL      = "example@banksalt.com"
CLIENT_USER_EMAIL = "example@banksalt.com"
BIT_BASE_URL      = "https://bit.banksalt.com"
QSEAL_X509        = OpenSSL::X509::Certificate.new(File.read('qseal.pem'))
QWAC_X509         = OpenSSL::X509::Certificate.new(File.read('qwac.pem'))
PKEY              = OpenSSL::PKey::RSA.new(File.read('private.pem'))

@payload                            = JSON.parse(File.read("payload.json"))
@payload['company']['email']        = CLIENT_EMAIL
@payload['representative']['email'] = CLIENT_USER_EMAIL

signature_helper = SignatureHelper.new(
  headers:     {"X-Request-ID" => SecureRandom.uuid},
  body:        @payload.to_json,
  certificate: QSEAL_X509,
  private_key: PKEY
)

@request_opts = {
  method:  "POST",
  url:     BIT_BASE_URL + "/sandbox/api/v1/tpps",
  headers: signature_helper.signed_headers,
  payload: signature_helper.body,
  verify_ssl: OpenSSL::SSL::VERIFY_NONE,
  ssl_client_cert: QWAC_X509,
  ssl_client_key:  PKEY
}
#########################################

begin
  response = RestClient::Request.execute(@request_opts)
  puts JSON.parse(response.body)
rescue => e
  puts e.class
  puts e.response&.body
  puts e.message
end