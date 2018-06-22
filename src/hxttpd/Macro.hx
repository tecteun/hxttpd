package hxttpd;
class Macro {

    macro public static function GetGitShortHead() 
	{
		var pos = haxe.macro.Context.currentPos();
		var p = try new sys.io.Process("git", ["rev-parse" ,"--short", "HEAD"]) catch ( e : Dynamic ) { trace("no git command found: " +  e); return { expr : EConst(CString("")), pos : pos }; };
		var output = 'Git short SHA1:' + p.stderr.readAll().toString() + p.stdout.readAll().toString();
		//Sys.command("git rev-parse --short HEAD > gitversion.txt");
		//var output = sys.io.File.read("svnversion.txt").readLine();
		output = output.split("\r").join("").split("\n").join("");
		return { expr : EConst(CString(output)), pos : pos };
	}

    macro public static function GetLastGitTag() 
	{
		var pos = haxe.macro.Context.currentPos();
		var p = try new sys.io.Process("git", ["describe" ,"--tags"]) catch ( e : Dynamic ) { trace("no git command found: " +  e); return { expr : EConst(CString("")), pos : pos }; };
		var output = p.stdout.readAll().toString();
		output = output.split("\r").join("").split("\n").join("");
        return { expr : EConst(CString(output)), pos : pos };
	}

    macro public static function GetVersion(?name:String = "", ?version:String = null) 
	{
		var date = Date.now().toString();
		if(version == null)
			version = GetLastGitTag();
		if(version == "unknown")
		    version = "1.0";
		version = StringTools.trim(version);
		name = StringTools.trim(name);
		
		var output = '$name $version, $date';

        return { expr : EConst(CString(output)), pos : haxe.macro.Context.currentPos() };
	}
}