ACL = {
    "student": ["request_certificate", "view_certificate"],
    "admin": ["approve_certificate", "sign_certificate", "verify_certificate"],
    "verifier": ["verify_certificate"]
}

def has_permission(role, action):
    return action in ACL.get(role, [])
