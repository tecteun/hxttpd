package ;
import hxttpd.Hxttpd;
class Test {
    public function new() {
        trace("creating Hxttpd");
        var n = new Hxttpd("0.0.0.0", 8080, ".", false);
		
		var reversePath = new haxe.io.Path("http://www.google.com/");
		var uid:Float = null;
		n.addRoute([~//], function(request, response, path, ?result:HxttpdRouteResult){ 
			if(path.file == "index" && path.ext == "html"){
				path = new haxe.io.Path(reversePath.dir + path.toString());
				uid = Date.now().getTime();
				response.headers.set('Set-Cookie', 'hxttpd_reverse_proxy=${uid};');
			}else if(request.headers.get("Cookie").indexOf('hxttpd_reverse_proxy=${uid}') > -1){
				path = new haxe.io.Path(reversePath.dir + path.toString());
			}
			response.httpStatusLine.status_code = 404;
			response.httpStatusLine.reason_phrase = "Not Found";
			response.headers.set("hxttpd-proxy-origin", path.toString());
			var h:haxe.Http = new haxe.Http(path.toString());
			trace('hxttpd_reverse_proxy=${uid};');
			trace(request.toString());
			trace('reverse proxy fetch Http.requestUrl("${path.toString()}")');
			var responseBytes = null;
			h.onData = function(d){
				responseBytes = haxe.io.Bytes.ofString(d);
			}
			h.onStatus = function(s){
				response.httpStatusLine.status_code = s;
				response.httpStatusLine.reason_phrase = Hxttpd.status_codes.get(s);	
			}
			h.request(false);
			if(h.responseHeaders != null)
				for(k in h.responseHeaders.keys()){
					if(k.toLowerCase() != "set-cookie")
						response.headers.set(k, h.responseHeaders.get(k));
				}
			return { bytes: responseBytes, response: response };
		});
		
        while(true){
			try{
				//use haxe mainloop for haxe.Timer etc.
				//haxe.EntryPoint.run();
				//will return immediately when workload is complete, ie all timers are done.
				Sys.sleep(1);
			}catch(e:Dynamic){
				trace('Unhandled global exception in haxe.MainLoop() -> $e');
			}
		}
    }

    static function main() {
        new Test();
    }
}