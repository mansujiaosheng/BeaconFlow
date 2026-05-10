// Export BeaconFlow metadata from Ghidra headless mode
//
// Usage:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary> \
//     -postScript ExportBeaconFlowMetadata.java <output.json> \
//     -deleteProject
//
// Output JSON schema (compatible with BeaconFlow load_metadata):
//   {
//     "input_path": "...",
//     "image_base": "0x...",
//     "functions": [
//       {
//         "name": "func_name",
//         "start": "0x...",
//         "end": "0x...",
//         "blocks": [
//           { "start": "0x...", "end": "0x...", "succs": ["0x..."] }
//         ]
//       }
//     ]
//   }

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileWriter;
import java.util.LinkedHashMap;
import java.util.ArrayList;

public class ExportBeaconFlowMetadata extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];

        FunctionManager fm = currentProgram.getFunctionManager();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        long imageBase = currentProgram.getImageBase().getOffset();
        String inputPath = currentProgram.getExecutablePath();
        if (inputPath == null) {
            inputPath = currentProgram.getName();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"input_path\": \"").append(escapeJson(inputPath)).append("\",\n");
        sb.append("  \"image_base\": \"0x").append(Long.toHexString(imageBase)).append("\",\n");
        sb.append("  \"functions\": [\n");

        Function func = fm.getFunctions(true).next();
        boolean firstFunc = true;
        for (Function f : fm.getFunctions(true)) {
            if (!firstFunc) {
                sb.append(",\n");
            }
            firstFunc = false;

            String name = f.getName();
            if (name == null || name.startsWith("FUN_")) {
                name = "0x" + Long.toHexString(f.getEntryPoint().getOffset());
            }

            long funcStart = f.getEntryPoint().getOffset();
            long funcEnd = f.getBody().getMaxAddress().getOffset() + 1;

            sb.append("    {\n");
            sb.append("      \"name\": \"").append(escapeJson(name)).append("\",\n");
            sb.append("      \"start\": \"0x").append(Long.toHexString(funcStart)).append("\",\n");
            sb.append("      \"end\": \"0x").append(Long.toHexString(funcEnd)).append("\",\n");
            sb.append("      \"blocks\": [\n");

            ArrayList<CodeBlock> blocks = new ArrayList<>();
            var codeBlocks = blockModel.getCodeBlocksContaining(f.getBody(), monitor);
            while (codeBlocks.hasNext()) {
                blocks.add(codeBlocks.next());
            }

            boolean firstBlock = true;
            for (CodeBlock cb : blocks) {
                if (!firstBlock) {
                    sb.append(",\n");
                }
                firstBlock = false;

                long blockStart = cb.getMinAddress().getOffset();
                long blockEnd = cb.getMaxAddress().getOffset() + 1;

                sb.append("        {\"start\": \"0x").append(Long.toHexString(blockStart)).append("\", ");
                sb.append("\"end\": \"0x").append(Long.toHexString(blockEnd)).append("\", ");
                sb.append("\"succs\": [");

                var destIter = cb.getDestinations(monitor);
                boolean firstSucc = true;
                while (destIter.hasNext()) {
                    CodeBlockReference dest = destIter.next();
                    long succStart = dest.getDestinationBlock().getMinAddress().getOffset();
                    if (!firstSucc) {
                        sb.append(", ");
                    }
                    firstSucc = false;
                    sb.append("\"0x").append(Long.toHexString(succStart)).append("\"");
                }

                sb.append("]}");
            }

            sb.append("\n      ]\n");
            sb.append("    }");
        }

        sb.append("\n  ]\n");
        sb.append("}\n");

        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(sb.toString());
        }

        println("[BeaconFlow] Exported " + fm.getFunctionCount() + " functions to " + outputPath);
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
