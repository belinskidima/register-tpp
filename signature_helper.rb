class SignatureHelper
  REQUIRED_HEADERS    = %w(Digest Date X-Request-ID)
  CONDITIONAL_HEADERS = %w(Psu-ID Psu-Corporate-ID TPP-Redirect-URI)

  attr_reader :certificate, :private_key, :headers, :body

  def initialize(headers: {}, body: "", certificate: nil, private_key: nil)
    @certificate = certificate
    @private_key = private_key
    @body        = body
    @headers     = headers.merge(
      "Digest"       => "SHA-256=#{Digest::SHA256.base64digest(body)}",
      "Date"         => Time.now.httpdate,
      "X-Request-ID" => SecureRandom.uuid,
      "Content-Type" => "application/json",
      "TPP-Signature-Certificate" => Base64.strict_encode64(@certificate.to_s)
    )
  end

  def signed_headers
    @headers.merge("Signature" => signature)
  end

  def signature
    return @signature if @signature
    signature = Base64.strict_encode64(private_key.sign("RSA-SHA256", signing_string))
    @signature = [
      "Signature keyId=\"SN=#{certificate.serial},DN=#{certificate.issuer}\"",
      "algorithm=\"rsa-sha256\"",
      "headers=\"#{signible_headers.keys.join(" ").downcase}\"",
      "signature=\"#{signature}\""
    ].join(",")
  end

  def signible_headers
    return @signible_headers if @signible_headers
    supported_headers = (REQUIRED_HEADERS + CONDITIONAL_HEADERS)
    @signible_headers = headers.select { |header| supported_headers.include?(header)  }
  end

  def signing_string
    signible_headers.each_with_object("") do |(header, value), object|
      object << "#{header.downcase}: #{value}\n"
    end.strip!
  end
end
