package saas.dev

import data

# 鉴权流程:
# 1. 解析apisix传递过来的数据
# 2. 根据组织-用户信息,获取到组织用户的角色信息
# 3. 根据角色信息, 查询到角色的策略信息
# 4. 根据策略信息,查询资源及资源操作信心
# 5. 根据此次请求的接口信息, 和用户的策略资源信息进行鉴权
# 6. 返回鉴权结果

# 注意: 一个用户可能存在多个角色, 根据角色,取策略的并集
# 更新 资源 --> 更新资源 和 操作  ====》 资源操作可以一体化
# 更新权限策略  ---> 更新的是权限 + 资源 + 操作列表
# 更新授权 ---》 更新主题的策略id +

# 定义鉴权结果
default response = {
	"allow": false,
	"status_code": 403
}

response = {
	"allow": allow
}

allow {
    user = data.user[user_id]
    user.username == "root"
}

allow {
	access_is_granted
}


# 根据token信息解析出来鉴权用户信息
user_info := user_info {
	[_, encoded] := split(input.request.headers.authorization, " ")
	[_, user_info, _] := io.jwt.decode(encoded)
}

user_id := format_int(user_info.user_id, 10)
org_id := input.request.headers.org_id
role_key := concat("_", [org_id, user_id])

role_lst[role] {
	role := data.org_user_role[role_key][_]
}

role_policies[policy] {
    response := http.send({
    	"url": "http://opa-manage-svc.saas-dev/manage/v1/saas/policies",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": {
        	"id": role_lst[role],
            "subject_type": "role",
            "org_id": org_id
        }
    })
    response.status_code == 200
    policy := response.body.data[_]
}

access_is_granted {
	some policy
    role_policies[policy]
    policy.effect == "allow"
    has_api_permissioin(policy)
    has_resource_permission(policy)
}

has_api_permissioin(policy) {
    upper(policy.api.method) == upper(input.request.method)
    glob.match(policy.api.api, ["/"], input.request.path)
}

has_resource_permission(policy) {
	res := get_resource(policy.res_arn, policy.arn_regx)
    arn_org_id := res[0][1]
    relative := res[0][2]
    arn_org_id == org_id
  	verify_resource(policy, relative)
}

verify_resource(policy, relative) {
	relative == "*"
	policy.code
}

verify_resource(policy, relative) {
	code := policy.code
    resource_key = concat("_", ["org", code])
    resources := data.Resources[resource_key][org_id]
   	target_id := get_target_id(policy.id_regex)
    res = resources[_]
    target_id == res
    relative == target_id
}

get_target_id(id_regex) = target_id {
	output := regex.find_all_string_submatch_n(id_regex, input.request.path, -1)
    count(output) == 1
	count(output[0]) == 2
	target_id := output[0][1]
}

get_resource(res_arn, arn_regex) = output {
	output := regex.find_all_string_submatch_n(arn_regex, res_arn, -1)
    count(output) == 1
	count(output[0]) == 3
}
