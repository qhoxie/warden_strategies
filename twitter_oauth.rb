## Twitter OAuth Strategy

Warden::Strategies.add(:oauth) do
  def authenticate!
    if params.include?('oauth_token') && credentials.authenticate!(params['oauth_token'])
      session.delete(:credential)
      success!(credentials)
    end

    redirect!(credentials.authentication_url)
  end

  def credentials
    @credentials ||= Credential.get(session[:credential] ||= Credential.create.id)
  end
end

## Make sure to add this in your init.rb or equivalent

Merb::BootLoader.after_app_loads do
  Warden::Manager.serialize_into_session {|cred| cred.to_s }
  Warden::Manager.serialize_from_session {|id| Credential.get(id) }
end

## And in your rack.rb or equivalent

use Warden::Manager do |manager|
  manager.default_strategies :oauth
end

## credential.rb

require 'oauth' # ~> oauth-0.3.2

class Credential
  include DataMapper::Resource
  extend Forwardable

  CONSUMER_KEY    = Merb::Config[:oauth][:consumer_key]
  CONSUMER_SECRET = Merb::Config[:oauth][:consumer_secret]

  property :id, DM::UUID, :nullable => false, :default => lambda { ::UUID.timestamp_create }, :index => true, :key => true
  property :access_token,   String, :length => 64
  property :access_secret,  String, :length => 64
  property :request_token,  String, :length => 64
  property :request_secret, String, :length => 64
  property :status,         Enum[:authenticated, nil]
  property :account_id,     Integer

  belongs_to :account

  def_delegators :id, :to_s
  def_delegators :request, :authorize_url

  def authenticate!(token)
    if token == self.request_token && verified?
      update(:status => :authenticated)
    end
  end

  def authentication_url
    authorize_url.gsub('authorize', 'authenticate')
  end

  def authenticated?
    self.status == :authenticated unless status.nil?
  end

  #TODO: you probably want to add more verification yourself
  def verified?
    !access.nil?
  end

  private

  def consumer
    @consumer ||= OAuth::Consumer.new(CONSUMER_KEY, CONSUMER_SECRET, :site => 'http://twitter.com')
  end

  def request
    @request ||= if request_token.nil? || request_secret.nil?
      request = consumer.get_request_token
      request if self.update(:request_token => request.token, :request_secret => request.secret)
    else
      OAuth::RequestToken.new(consumer, request_token, request_secret)
    end
  end

  def access
    @access ||= if access_token.nil? || access_secret.nil?
      access = request.get_access_token
      access if update(:access_token => access.token, :access_secret => access.secret)
    else
      OAuth::AccessToken.new(consumer, access_token, access_secret)
    end
  end
end
