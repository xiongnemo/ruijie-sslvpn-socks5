// Export static pseudocode and string cross-references; never executes the target.
// @category SSLVPN
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ExportProtocol extends GhidraScript {
    public void run() throws Exception {
        File dir = new File(getScriptArgs()[0]); dir.mkdirs();
        TreeSet<Function> selected = new TreeSet<>((a,b)->a.getEntryPoint().compareTo(b.getEntryPoint()));
        try(PrintWriter w = new PrintWriter(new File(dir,"strings.tsv"),"UTF-8")) {
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while(it.hasNext() && !monitor.isCancelled()) {
                Data d=it.next(); Object v=d.getValue(); if(!(v instanceof String)) continue;
                String s=(String)v;
                ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                while(refs.hasNext()) {
                    Reference r=refs.next(); Function f=getFunctionContaining(r.getFromAddress());
                    w.println(d.getAddress()+"\t"+(f==null?"-":f.getEntryPoint())+"\t"+s.replace("\n","\\n").replace("\r","\\r"));
                    // First-party strings precede statically linked curl/OpenSSL strings.
                    if(f!=null && d.getAddress().getOffset()<0x1802a0000L && s.matches("(?is).*(sslvpn|login|cookie|tunnel|send_data|recv_data|ctrl_data|IPTUN|virt_ip|OTP|auth|HttpService|OpenSslService|Set cookie|ping).*")) selected.add(f);
                }
            }
        }
        // An explicit address list allows follow-up decompilation from the saved project.
        String[] args=getScriptArgs();
        if(args.length>1) { selected.clear(); for(int i=1;i<args.length;i++) for(String a:args[i].split(",")) { Function f=getFunctionContaining(toAddr(a)); if(f!=null)selected.add(f); else { ReferenceIterator rs=currentProgram.getReferenceManager().getReferencesTo(toAddr(a)); while(rs.hasNext()){Function rf=getFunctionContaining(rs.next().getFromAddress());if(rf!=null)selected.add(rf);} } } }
        DecompInterface decomp=new DecompInterface(); decomp.openProgram(currentProgram);
        try(PrintWriter index=new PrintWriter(new File(dir,"functions.tsv"),"UTF-8")) {
            for(Function f:selected) {
                if(monitor.isCancelled())break;
                DecompileResults r=decomp.decompileFunction(f,90,monitor);
                String name=f.getEntryPoint().toString(); index.println(name+"\t"+f.getName()+"\t"+r.getErrorMessage());
                try(PrintWriter w=new PrintWriter(new File(dir,name+".c"),"UTF-8")) {
                    w.println("// STATIC DECOMPILATION: "+currentProgram.getExecutablePath()+" "+f.getEntryPoint()+" "+f.getName());
                    if(r.decompileCompleted())w.println(r.getDecompiledFunction().getC()); else w.println(r.getErrorMessage());
                }
            }
        } finally {decomp.dispose();}
        println("Exported "+selected.size()+" functions to "+dir);
    }
}
