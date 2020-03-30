require 'twilio-ruby'

class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  def self.gen_token
    account_sid = ENV['TWILIO_ACCOUNT_SID']
    api_key = ENV['TWILIO_API_SID']
    api_secret = ENV['TWILIO_API_SECRET']

    identity = 'bjarne-hinkel'

    token = Twilio::JWT::AccessToken.new(account_sid, api_key, api_secret, [], identity: identity);

    grant = Twilio::JWT::AccessToken::VideoGrant.new
    grant.room = 'BjarneDevelopment'
    token.add_grant(grant)

    puts token.to_jwt
  end
end
