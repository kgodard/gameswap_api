class Users::RegistrationsController < Devise::RegistrationsController

  skip_before_filter :verify_authenticity_token

  respond_to :json
  def create
    # Create the user
    build_resource(sign_up_params)
    # Try to save them
    if resource.save
      sign_in resource
      render status: 200,
        json: {
          success: true,
          info: "Registered",
          data: {
            user: resource,
            auth_token: current_user.authentication_token
          }
        }
    else
      # Otherwise fail
      render status: :unprocessable_entity,
        json: {
          success: false,
          info: resource.errors,
          data: {}
        }
    end
  end
end

