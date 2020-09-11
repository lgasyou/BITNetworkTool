import os from 'os'
import fs from 'fs'

import {portal} from "./portal.js"

const USER_PROFILE_PATH = './profile.json'
const LOGIN_ACTION = 'login'
const LOGIN_URL = 'http://10.0.0.55/cgi-bin/srun_portal'

function notify(title, message) {
  console.log(`${title}: ${message}`)
}

function loadUserInfo(filename) {
  let data = fs.readFileSync(filename, "utf8")
  return JSON.parse(data)
}

function getIpAddress() {
  let networkInterfaces = JSON.stringify(os.networkInterfaces())
  let ipRegex = /10\.\d+\.\d+\.\d+/
  return ipRegex.exec(networkInterfaces)[0]
}

function main() {
  let profile = loadUserInfo(USER_PROFILE_PATH)
  let ip = getIpAddress()
  let data = {
    action: process.argv[2] || LOGIN_ACTION,
    username: profile.username,
    password: profile.password,
    ac_id: '1',
    ip: ip,
  }

  portal(LOGIN_URL, data, (res) => {
    let title = (data.action === LOGIN_ACTION) ? '校园网登录' : '校园网注销'
    let request_message = res.suc_msg || res.error_msg || 'ok'
    let message = `ip: ${res.client_ip}, ${request_message}`
    notify(title, message)
  })
}

main()
