require 'erb'
require 'json'
require 'jwt'
require 'net/http'
require 'openssl'

class GoogleApi
  GOOGLE_API_ROOT = 'www.googleapis.com'

  def initialize(service_id, service_key, user)
    @service_id = service_id
    @service_key = OpenSSL::PKey::RSA.new(service_key)
    @user = user
    @credentials = {}
  end

  def groups_for(email)
    email_encoded = ERB::Util.url_encode(email)

    scopes = [scope('auth/admin.directory.group.readonly')]
    response = make_request("/admin/directory/v1/groups?userKey=#{email_encoded}", scopes)
    response['groups'].map { |g| g['email'] }
  end

  def roles_for(email, customer_id)
    email_encoded = ERB::Util.url_encode(email)
    customer_id_encoded = ERB::Util.url_encode(customer_id)

    scopes = [scope('auth/admin.directory.rolemanagement.readonly')]

    org_roles = make_request("/admin/directory/v1/customer/#{customer_id_encoded}/roles", scopes)
    user_roles = make_request("/admin/directory/v1/customer/#{customer_id_encoded}/roleassignments?userKey=#{email_encoded}", scopes)

    user_roles['items'].map do |user_role_assignment|
      org_role = org_roles['items'].detect{|r| r['roleId'] == user_role_assignment['roleId'] }
      next unless org_role

      {
        'roleId' => org_role['roleId'],
        'roleName' => org_role['roleName'],
        'roleDescription' => org_role['roleDescription'],
      }
    end
  end

  private

  def access_token_for(scopes)
    key = scopes.sort.to_json

    if credentials_valid_for(key)
      return @credentials[key][:access_token]
    end

    @credentials[key] = get_credentials(scopes)
    @credentials[key][:access_token]
  end

  def credentials_valid_for(scopes_key)
    return (@credentials[scopes_key] && @credentials[scopes_key][:expires_at] > Time.now)
  end

  def get_credentials(scopes)
    http = Net::HTTP.new(GOOGLE_API_ROOT, 443)
    http.use_ssl = true

    request = Net::HTTP::Post.new('/oauth2/v3/token')

    payload = {
      'iss'   => @service_id,
      'sub'   => @user,
      'scope' => scopes.join(' '),
      'aud'   => "https://#{GOOGLE_API_ROOT}/oauth2/v3/token",
      'exp'   => (Time.now + (60 * 60)).to_i,
      'iat'   => Time.now.to_i
    }

    token = JWT.encode(payload, @service_key, 'RS256')

    request.set_form_data({ 'assertion' => token, 'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer' })

    response = http.request(request)
    json_response = JSON.parse(response.body)

    {
      expires_at: Time.at(payload['exp']),
      access_token: json_response['access_token']
    }
  end

  def make_request(endpoint, scopes, opts = {})
    token = access_token_for(scopes)

    http = Net::HTTP.new(GOOGLE_API_ROOT, 443)
    http.use_ssl = true

    request = Net::HTTP::Get.new(endpoint)
    request['Authorization'] = "Bearer #{token}"

    JSON.parse(http.request(request).body)
  end

  def scope(path)
    "https://#{GOOGLE_API_ROOT}/#{path}"
  end
end
