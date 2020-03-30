class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  def gen_token
    ACCOUNT_SID = ENV['TWILIO_ACCOUNT_SID']
    API_KEY = ENV['TWILIO_API_SID']
    API_SECRET = ENV['TWILIO_API_SECRET']

    identity = 'bjarne-hinkel'

    token = Twilio::JWT::AccessToken.new(ACCOUNT_SID, API_KEY, API_SECRET, [], identity: identity);

    grant = Twilio::JWT::AccessToken::VideoGrant.new
    grant.room = 'BjarneDevelopment'
    token.add_grant(grant)

    puts token.to_jwt
  end
end
