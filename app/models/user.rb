class User
  include Mongoid::Document
  include Mongoid::Timestamps

  field :email, type: String
  field :first_name, type: String
  field :middle_name, type: String
  field :last_name, type: String
  field :initials, type: String
# TODO need to look at this again
  field :employee_id, type: String
  field :phone, type: String
  field :status, type: Integer
  field :avatar, type: String
end
