// Read-only export script for REA MCP.
// Run by Ghidra's analyzeHeadless using -postScript.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ExportAnalysis extends GhidraScript {
    private String quote(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private String number(long value) {
        return Long.toString(value);
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 5) throw new IllegalArgumentException("Expected output path, max functions, max decompiles, max strings, max instructions.");
        Path output = Path.of(args[0]);
        int maxFunctions = Integer.parseInt(args[1]);
        int maxDecompiles = Integer.parseInt(args[2]);
        int maxStrings = Integer.parseInt(args[3]);
        int maxInstructions = Integer.parseInt(args[4]);

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.openProgram(currentProgram);

        StringBuilder functionsJson = new StringBuilder("[");
        int functionCount = 0;
        int decompiledCount = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && functionCount < maxFunctions && !monitor.isCancelled()) {
            Function function = functions.next();
            if (functionCount > 0) functionsJson.append(',');
            String name = function.getName();
            String address = function.getEntryPoint().toString();
            String signature = function.getSignature().toString();
            long size = function.getBody().getNumAddresses();

            String pseudocode = "";
            if (decompiledCount < maxDecompiles) {
                DecompileResults result = decompiler.decompileFunction(function, 5, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    pseudocode = result.getDecompiledFunction().getC();
                    decompiledCount++;
                }
            }

            List<String> assembly = new ArrayList<>();
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext() && assembly.size() < maxInstructions) {
                Instruction instruction = instructions.next();
                assembly.add(instruction.getAddress().toString() + ": " + instruction.toString());
            }

            functionsJson.append("{")
                .append("\"name\":").append(quote(name)).append(',')
                .append("\"address\":").append(quote(address)).append(',')
                .append("\"size\":").append(number(size)).append(',')
                .append("\"signature\":").append(quote(signature)).append(',')
                .append("\"decompilation\":").append(quote(pseudocode)).append(',')
                .append("\"assembly\":[");
            for (int i = 0; i < assembly.size(); i++) {
                if (i > 0) functionsJson.append(',');
                functionsJson.append(quote(assembly.get(i)));
            }
            functionsJson.append("]}");
            functionCount++;
        }
        functionsJson.append(']');

        StringBuilder stringsJson = new StringBuilder("[");
        int stringCount = 0;
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && stringCount < maxStrings && !monitor.isCancelled()) {
            Data item = data.next();
            Object value;
            try { value = item.getValue(); } catch (Exception ignored) { continue; }
            if (!(value instanceof String)) continue;
            String text = (String)value;
            if (text.isEmpty() || text.length() > 4096) continue;
            if (stringCount > 0) stringsJson.append(',');
            stringsJson.append("{\"address\":").append(quote(item.getAddress().toString()))
                .append(",\"value\":").append(quote(text)).append('}');
            stringCount++;
        }
        stringsJson.append(']');

        String language = currentProgram.getLanguageID().getIdAsString();
        String compiler = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        String format = currentProgram.getExecutableFormat();
        String executablePath = currentProgram.getExecutablePath();
        String minAddress = currentProgram.getMinAddress() == null ? "" : currentProgram.getMinAddress().toString();
        String maxAddress = currentProgram.getMaxAddress() == null ? "" : currentProgram.getMaxAddress().toString();

        StringBuilder json = new StringBuilder();
        json.append("{")
            .append("\"analysisId\":\"pending\",")
            .append("\"filename\":").append(quote(currentProgram.getName())).append(',')
            .append("\"analyzedAt\":").append(quote(java.time.Instant.now().toString())).append(',')
            .append("\"info\":{")
            .append("\"format\":").append(quote(format)).append(',')
            .append("\"language\":").append(quote(language)).append(',')
            .append("\"compiler\":").append(quote(compiler)).append(',')
            .append("\"executablePath\":").append(quote(executablePath)).append(',')
            .append("\"minAddress\":").append(quote(minAddress)).append(',')
            .append("\"maxAddress\":").append(quote(maxAddress)).append(',')
            .append("\"functionCount\":").append(functionCount).append(',')
            .append("\"decompiledCount\":").append(decompiledCount).append(',')
            .append("\"stringCount\":").append(stringCount)
            .append("},")
            .append("\"functions\":").append(functionsJson).append(',')
            .append("\"strings\":").append(stringsJson)
            .append("}");

        Files.createDirectories(output.getParent());
        Files.writeString(output, json.toString());
        decompiler.dispose();
        println("REA MCP exported " + functionCount + " functions and " + stringCount + " strings to " + output);
    }
}
