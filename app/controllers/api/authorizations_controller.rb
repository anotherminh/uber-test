class Api::AuthorizationsController < ApplicationController
	before_action :require_authorization, only: :use_uber

  def echo
    render json: params
  end

  def authorize
    # render nil if params[:token] != ENV[slack_token]
    # if auth.nil?
    # 	# find the user
    # 	# validate if user has uber tokens
    # 	# if so, there should be location info
    # 	# call a car for user
    # 	use_uber
    # end
  end

  # this is only for new user, connecting its slack acc w/ uber acc
  # this is the callback for authorizing new user
  def connect_uber
    params = {
      client_secret: ENV['uber_client_secret'],
      client_id:     ENV['uber_client_id'],
      grant_type:    'authorization_code',
      # redirect_uri   ENV[''],
      code:          params[:code]
    }
    # post request to uber
    resp = Net::HTTP.post_form(URI.parse('https://login.uber.com/oauth/v2/token'), params)

    access_token = resp['access_token']

    Authorization.find_by(session_token: session[:session_token])
                 .update(uber_auth_token: access_token)

    render text: "uber auth success, access_token: #{access_token}"
  end

  def use_uber
  	# here order car
  end

	def connect_slack
		slack_auth_params = {
			client_secret: ENV['slack_client_secret'],
			client_id: ENV['slack_client_id'],
			redirect_uri: ENV['slack_redirect'],
			code: my_params[:code]
		}

		resp = Net::HTTP.post_form(URI.parse('https://slack.com/api/oauth.access'), slack_auth_params)

		access_token = resp['access_token']
		#
		# Authorization.find_by(session_token: session[:session_token])
		# 						 .update(slack_auth_token: access_token)

		render text: "slack auth success, access_token: #{resp}"
	end

	def connect_slack_success
		render text: "slack auth success (other method)"
	end

  private

  def require_authorization
  	auth = Authorization.find_by(slack_user_id: my_params[:user_id])

  	if auth.nil?
  		session[:session_token] = Authorization.session_token

  		auth = Authorization.new(slack_user_id: my_params[:user_id], oauth_session_token: session[:session_token])

  		# TODO: add model level validation
  		auth.save

  		# register our app with uber and a url before all these
  		# need a router for uber to make request
  		render json: { "text" => "https://login.uber.com/oauth/v2/authorize?response_type=code&client_id=B4K8XNeyIq4qsI0QqCN8INGv7Ztn1XIL" }
  		# redirect_to "https://login.uber.com/oauth/v2/authorize?response_type=code&client_id=B4K8XNeyIq4qsI0QqCN8INGv7Ztn1XIL"
  	else
			render json: { "text" => "Did not succeed" }
		end
  end

	def my_params
		params.permit(:user_id, :code)
	end
end
