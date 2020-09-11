import request from 'request'
import Hashes from './hashes.js'

function xEncode(str, key) {
    if(str == "") {
        return "";
    }
    let v = s(str, true),
        k = s(key, false);
    if(k.length<4) {
        k.length=4;
    }
    let n=v.length-1,
        z=v[n],
        y=v[0],
        c=0x86014019|0x183639A0,
        m,
        e,
        p,
        q=Math.floor(6+52/(n+1)),
        d=0;
    while (0<q--) {
        d=d+c&(0x8CE0D9BF|0x731F2640);
        e=d>>>2&3;
        for(p=0;p<n;p++) {
            y=v[p+1];
            m=z>>>5^y<<2;
            m+=(y>>>3^z<<4)^(d^y);
            m+=k[(p&3)^e]^z;
            z=v[p]=v[p]+m&(0xEFB8D130|0x10472ECF);
        }
        y=v[0];
        m=z>>>5^y<<2;
        m+=(y>>>3^z<<4)^(d^y);
        m+=k[(p&3)^e]^z;
        z=v[n]=v[n]+m&(0xBB390742|0x44C6F8BD);
    }

    function s(a,b) {
        var c=a.length,v=[];
        for(var i=0;i<c;i+=4) {
            v[i>>2]=a.charCodeAt(i)|a.charCodeAt(i+1)<<8|a.charCodeAt(i+2)<<16|a.charCodeAt(i+3)<<24;
        }
        if(b) {
            v[v.length]=c;
        }
        return v;
    }

    function l(a,b) {
        var d=a.length,c=(d-1)<<2;
        if(b) {
            var m=a[d-1];
            if((m<c-3)||(m>c))
                return null;
            c = m;
        }
        for (var i=0;i<d;i++) {
            a[i]=String.fromCharCode(a[i]&0xff,a[i]>>>8&0xff,a[i]>>>16&0xff,a[i]>>>24&0xff);
        }
        if(b) {
            return a.join('').substring(0, c);
        } else {
            return a.join('');
        }
    }

    return l(v, false);
}

function getJSON(url, param, callback) {
    return request({
        url: url,
        method: 'GET',
        qs: param,
        json: true
    }, (error, response, body) => {
        callback(body)
    })
}

export function portal(url, data, callback) {
    if (url.match("srun_portal") != null || url.match("get_challenge") != null) {
        var enc = "s"+"run"+"_bx1",
            n=200,
            type=1,
            base64 = new Hashes.Base64();
        if (data.action == "login") {   //login
            let $data = data;
            return getJSON(url.replace("srun_portal", "get_challenge"), {"username": $data.username, "ip": $data.ip}, function(data) {
                var token = "";
                if (data.res != "ok") {
                    return;
                }
                token = data.challenge;
                $data.info = "{SRBX1}"+base64.encode(xEncode(JSON.stringify({"username":$data.username, "password":$data.password, "ip":$data.ip, "acid":$data.ac_id, "enc_ver":enc}), token));
                var hmd5 = new Hashes.MD5().hex_hmac(token, data.password);
                $data.password = "{MD5}"+hmd5;
                $data.chksum = new Hashes.SHA1().hex(token+$data.username+token+hmd5+token+$data.ac_id+token+$data.ip+token+n+token+type+token+$data.info);
                $data.n = n;
                $data.type = type;
                return getJSON(url, $data, callback);
            });
        } else if (data.action == "logout") {   //logout
            let $data = data;
            return getJSON(url.replace("srun_portal", "get_challenge"), {"username": $data.username, "ip": $data.ip}, function(data) {
                var token = "";
                if (data.res != "ok") {
                    return;
                }
                token = data.challenge;
                $data.info = "{SRBX1}"+base64.encode(xEncode(JSON.stringify({"username":$data.username, "ip":$data.ip, "acid":$data.ac_id,"enc_ver":enc}), token));
                var str = token+$data.username+token+$data.ac_id+token+$data.ip+token+n+token+type+token+$data.info;
                $data.chksum = new Hashes.SHA1().hex(str);
                $data.n = n;
                $data.type = type;
                return getJSON(url, $data, callback);
            });
        } else {
            return getJSON(url, data, callback);
        }
    }
    return getJSON(url, data, callback);
}
