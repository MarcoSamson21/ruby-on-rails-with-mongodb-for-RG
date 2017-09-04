class Api::V1::UsersController < Api::V1::ApiController
  #BOILER PLATE CODE

  #GET /api/v1/users
  def index
    @users = User.all
  end

  # POST /api/v1/users
  def create
  end

  # PUT /api/v1/users/:id
  def update
  end

  # DESTROY /api/v1/users/:id
  def destroy
  end

  #GET /api/v1/users/:id
  def show
  end
end
