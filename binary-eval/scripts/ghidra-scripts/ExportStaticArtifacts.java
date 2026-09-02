import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;


public class ExportStaticArtifacts extends GhidraScript {

    @Override
    public void run() throws Exception {

        println("ExportStaticArtifacts started.");

        String[] args = getScriptArgs();

        if (args.length < 1) {
            throw new IllegalArgumentException(
                "Expected output directory argument."
            );
        }

        File outputDir = new File(args[0]);
        File decompiledDir = new File(outputDir, "decompiled");
        File assemblyDir = new File(outputDir, "assembly");
        File cfgDir = new File(outputDir, "cfg");

        outputDir.mkdirs();
        decompiledDir.mkdirs();
        assemblyDir.mkdirs();
        cfgDir.mkdirs();

        println("Output directory: " + outputDir.getAbsolutePath());
        println("Program: " + currentProgram.getName());

        exportFunctions(outputDir);
        exportImports(outputDir);
        exportDecompiledFunctions(decompiledDir);
        exportAssembly(assemblyDir);
        exportCFGs(cfgDir);
        exportCallGraph(outputDir);

        println("ExportStaticArtifacts completed.");
    }


    private void exportFunctions(File outputDir) throws Exception {

        File outputFile = new File(
            outputDir,
            "functions.tsv"
        );

        FunctionManager functionManager =
            currentProgram.getFunctionManager();

        FunctionIterator functions =
            functionManager.getFunctions(true);

        try (
            PrintWriter writer = new PrintWriter(
                new FileWriter(outputFile)
            )
        ) {

            writer.println(
                "address\tname\tsignature\tcalling_convention"
            );

            while (functions.hasNext()) {

                Function function = functions.next();

                String address =
                    function.getEntryPoint().toString();

                String name =
                    function.getName();

                String signature =
                    sanitize(function.getSignature().toString());

                String callingConvention =
                    function.getCallingConventionName();

                writer.printf(
                    "%s\t%s\t%s\t%s%n",
                    address,
                    sanitize(name),
                    signature,
                    sanitize(callingConvention)
                );
            }
        }

        println(
            "Exported functions.tsv: "
            + outputFile.getAbsolutePath()
        );
    }


    private void exportDecompiledFunctions(
        File decompiledDir
    ) throws Exception {

        DecompInterface decompiler =
            new DecompInterface();

        decompiler.openProgram(currentProgram);

        FunctionManager functionManager =
            currentProgram.getFunctionManager();

        FunctionIterator functions =
            functionManager.getFunctions(true);

        int exported = 0;
        int failed = 0;

        while (functions.hasNext()) {

            monitor.checkCancelled();

            Function function = functions.next();

            DecompileResults results =
                decompiler.decompileFunction(
                    function,
                    60,
                    monitor
                );

            if (!results.decompileCompleted()) {

                println(
                    "Decompiler failed for: "
                    + function.getName()
                    + " @ "
                    + function.getEntryPoint()
                );

                failed++;
                continue;
            }

            String code =
                results
                    .getDecompiledFunction()
                    .getC();

            String filename =
                function.getEntryPoint().toString()
                + "_"
                + safeFilename(function.getName())
                + ".c";

            File outputFile =
                new File(
                    decompiledDir,
                    filename
                );

            try (
                PrintWriter writer =
                    new PrintWriter(
                        new FileWriter(outputFile)
                    )
            ) {
                writer.print(code);
            }

            exported++;
        }

        decompiler.dispose();

        println(
            "Decompiled functions exported: "
            + exported
        );

        println(
            "Decompilation failures: "
            + failed
        );
    }


    private String sanitize(String value) {

        if (value == null) {
            return "";
        }

        return value
            .replace("\t", " ")
            .replace("\r", " ")
            .replace("\n", " ");
    }


    private String safeFilename(String value) {

        if (value == null || value.isEmpty()) {
            return "unnamed";
        }

        return value.replaceAll(
            "[^A-Za-z0-9._-]",
            "_"
        );
    }

    private void exportImports(File outputDir) throws Exception {

    File outputFile = new File(
        outputDir,
        "imports.tsv"
    );

        SymbolTable symbolTable =
            currentProgram.getSymbolTable();

        SymbolIterator symbols =
            symbolTable.getExternalSymbols();

        int count = 0;

        try (
            PrintWriter writer = new PrintWriter(
                new FileWriter(outputFile)
            )
        ) {

            writer.println(
                "library\tname\taddress"
            );

            while (symbols.hasNext()) {

                monitor.checkCancelled();

                Symbol symbol = symbols.next();

                String library = "";

                if (symbol.getParentNamespace() != null) {
                    library =
                        symbol.getParentNamespace().getName();
                }

                String name =
                    symbol.getName();

                String address = "";

                if (symbol.getAddress() != null) {
                    address =
                        symbol.getAddress().toString();
                }

                writer.printf(
                    "%s\t%s\t%s%n",
                    sanitize(library),
                    sanitize(name),
                    sanitize(address)
                );

                count++;
            }
        }

        println(
            "Exported imports.tsv entries: "
            + count
        );

        println(
            "imports.tsv: "
            + outputFile.getAbsolutePath()
        );
    }

    private void exportAssembly(File assemblyDir) throws Exception {

        FunctionManager functionManager =
            currentProgram.getFunctionManager();

        Listing listing =
            currentProgram.getListing();

        FunctionIterator functions =
            functionManager.getFunctions(true);

        int exported = 0;

        while (functions.hasNext()) {

            monitor.checkCancelled();

            Function function = functions.next();

            String filename =
                function.getEntryPoint().toString()
                + "_"
                + safeFilename(function.getName())
                + ".asm";

            File outputFile =
                new File(assemblyDir, filename);

            try (
                PrintWriter writer =
                    new PrintWriter(
                        new FileWriter(outputFile)
                    )
            ) {

                writer.println(
                    "; Function: " + function.getName()
                );

                writer.println(
                    "; Entry: " + function.getEntryPoint()
                );

                writer.println();

                InstructionIterator instructions =
                    listing.getInstructions(
                        function.getBody(),
                        true
                    );

                while (instructions.hasNext()) {

                    monitor.checkCancelled();

                    Instruction instruction =
                        instructions.next();

                    writer.printf(
                        "%s\t%s%n",
                        instruction.getAddress(),
                        instruction.toString()
                    );
                }
            }

            exported++;
        }

        println(
            "Assembly functions exported: "
            + exported
        );
    }
    
    private void exportCFGs(File cfgDir) throws Exception {

        BasicBlockModel blockModel =
            new BasicBlockModel(currentProgram);

        FunctionManager functionManager =
            currentProgram.getFunctionManager();

        FunctionIterator functions =
            functionManager.getFunctions(true);

        int exported = 0;

        while (functions.hasNext()) {

            monitor.checkCancelled();

            Function function = functions.next();

            String filename =
                function.getEntryPoint().toString()
                + "_"
                + safeFilename(function.getName())
                + ".dot";

            File outputFile =
                new File(cfgDir, filename);

            try (
                PrintWriter writer =
                    new PrintWriter(
                        new FileWriter(outputFile)
                    )
            ) {

                writer.println("digraph cfg {");
                writer.println(
                    "  label=\"" + sanitize(function.getName()) + "\";"
                );
                writer.println("  node [shape=box];");

                CodeBlockIterator blocks =
                    blockModel.getCodeBlocksContaining(
                        function.getBody(),
                        monitor
                    );

                while (blocks.hasNext()) {

                    monitor.checkCancelled();

                    CodeBlock block = blocks.next();

                    String source =
                        block.getFirstStartAddress().toString();

                    writer.printf(
                        "  \"%s\";%n",
                        source
                    );

                    CodeBlockReferenceIterator destinations =
                        block.getDestinations(monitor);

                    while (destinations.hasNext()) {

                        CodeBlockReference reference =
                            destinations.next();

                        CodeBlock destination =
                            reference.getDestinationBlock();

                        if (destination == null) {
                            continue;
                        }

                        String target =
                            destination
                                .getFirstStartAddress()
                                .toString();

                        // Keep only control-flow edges that remain
                        // inside the current function.
                        if (!function.getBody().contains(
                                destination.getFirstStartAddress())) {
                            continue;
                        }

                        writer.printf(
                            "  \"%s\" -> \"%s\";%n",
                            source,
                            target
                        );
                    }
                }

                writer.println("}");
            }

            exported++;
        }

        println(
            "CFGs exported: "
            + exported
        );
    }

    private void exportCallGraph(File outputDir) throws Exception {

    File outputFile = new File(
        outputDir,
        "callgraph.dot"
    );

        FunctionManager functionManager =
            currentProgram.getFunctionManager();

        ReferenceManager referenceManager =
            currentProgram.getReferenceManager();

        FunctionIterator functions =
            functionManager.getFunctions(true);

        Set<String> emittedNodes = new HashSet<>();
        Set<String> emittedEdges = new HashSet<>();

        int edgeCount = 0;

        try (
            PrintWriter writer =
                new PrintWriter(
                    new FileWriter(outputFile)
                )
        ) {

            writer.println("digraph callgraph {");
            writer.println("  node [shape=box];");

            while (functions.hasNext()) {

                monitor.checkCancelled();

                Function caller = functions.next();

                String callerAddress =
                    caller.getEntryPoint().toString();

                String callerLabel =
                    callerAddress
                    + "\\n"
                    + sanitize(caller.getName());

                String callerNode =
                    "\"" + callerAddress +
                    "\" [label=\"" +
                    callerLabel +
                    "\"];";

                if (emittedNodes.add(callerNode)) {
                    writer.println(
                        "  " + callerNode
                    );
                }

                AddressIterator addresses =
                    caller.getBody().getAddresses(true);

                while (addresses.hasNext()) {

                    monitor.checkCancelled();

                    Address address =
                        addresses.next();

                    Reference[] references =
                        referenceManager.getReferencesFrom(
                            address
                        );

                    for (Reference reference : references) {

                        monitor.checkCancelled();

                        if (!reference
                                .getReferenceType()
                                .isCall()) {
                            continue;
                        }

                        Function callee =
                            functionManager.getFunctionAt(
                                reference.getToAddress()
                            );

                        if (callee == null) {
                            continue;
                        }

                        String calleeAddress =
                            callee
                                .getEntryPoint()
                                .toString();

                        String calleeLabel =
                            calleeAddress
                            + "\\n"
                            + sanitize(callee.getName());

                        String calleeNode =
                            "\"" + calleeAddress +
                            "\" [label=\"" +
                            calleeLabel +
                            "\"];";

                        if (emittedNodes.add(calleeNode)) {
                            writer.println(
                                "  " + calleeNode
                            );
                        }

                        String edge =
                            "\"" + callerAddress +
                            "\" -> \"" +
                            calleeAddress +
                            "\";";

                        if (emittedEdges.add(edge)) {

                            writer.println(
                                "  " + edge
                            );

                            edgeCount++;
                        }
                    }
                }
            }

            writer.println("}");
        }

        println(
            "Call graph nodes exported: "
            + emittedNodes.size()
        );

        println(
            "Call graph edges exported: "
            + edgeCount
        );

        println(
            "callgraph.dot: "
            + outputFile.getAbsolutePath()
        );
    }
}