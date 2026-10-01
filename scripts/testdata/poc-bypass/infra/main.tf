resource"terraform_data""a"{
  input = 1
}
/**/ data "external" "b" {
  program = ["sh", "-c", "echo '{}'"]
}
module "m" {
  source = "../mod"
}
