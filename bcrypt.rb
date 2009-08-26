Warden::Strategies.add(:bcrypt) do
  def valid?
    params[:username] || params[:password]
  end
  
  def authenticate!
    return fail! unless user = User.first(:username => params[:username])
    
    if user.encrypted_password == params[:password]
      success!(user)
    else
      errors.add(:login, "Username or Password incorrect")
      fail!
    end
  end
end


## User Models

### ActiveRecord

class User < ActiveRecord::Base
  attr_accessor :password, :password_confirmation  
  
  validates_present         :encrypted_password
  validates_confirmation_of :password,  :if => :password
  
  def password=(pass)
    @password = pass
    self.encrypted_password =  pass.nil? ? nil : ::BCrypt::Password.create(pass)
  end
  
  def encrypted_password
    @encrypted_password ||= begin
      ep = read_attribute(encrypted_password)
      ep.nil? ? nil : ::BCrypt::Password.new(ep)
    end
  end
end


## DataMapper

class User
  attr_accessor :password, :password_confirmation
  
  include DataMapper::Resource
  
  property :id, Serial
  property :encrypted_password, BCryptHash, :nullable => false
  
  validates_is_confirmed :password
  
  def password=(pass)
    @password = pass
    self.encrypted_password = pass
  end
end
