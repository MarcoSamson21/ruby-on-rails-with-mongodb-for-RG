class Api::V1::ApiController < ActionController::Base
  before_action :authenticate
  before_action :authenticate_user_from_token!


  rescue_from CanCan::AccessDenied do |exception|
    render json: {error: 'Permission denied'}, status: 403, layout: false
  end

  def authenticate
    render json: {error: 'Unauthorized, Please contact to the vendor.'}, status: 401 unless request.headers[:HTTP_ACCESS_TOKEN] == ENV['ACCESS_TOKEN']
  end

  def authenticate_user_from_token!
    user_email = request.headers[:HTTP_USER_EMAIL].presence
    user = user_email && User.find_by(email: user_email)
    if user && Devise.secure_compare(user.token, request.headers[:HTTP_USER_TOKEN])
      sign_in user, store: false
    end
  end
end
