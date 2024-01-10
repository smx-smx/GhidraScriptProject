/**
 * A Ghidra script to chainload another Script bundled in an OSGI module
 * Written by Stefano Moioli <smxdev4@gmail.com>
 */
import db.Transaction;
import generic.stl.Pair;
import ghidra.app.nav.Navigatable;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.framework.data.DomainObjectFileListener;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramOverlayAddressSpace;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleWiring;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.stream.Stream;

public class InvokeBundleScript extends GhidraScript {
    private class DummyProgram implements Program {
        @Override
        public Listing getListing() {
            return new Listing() {
                @Override
                public CodeUnit getCodeUnitAt(Address address) {
                    return null;
                }

                @Override
                public CodeUnit getCodeUnitContaining(Address address) {
                    return null;
                }

                @Override
                public CodeUnit getCodeUnitAfter(Address address) {
                    return null;
                }

                @Override
                public CodeUnit getCodeUnitBefore(Address address) {
                    return null;
                }

                @Override
                public CodeUnitIterator getCodeUnitIterator(String s, boolean b) {
                    return null;
                }

                @Override
                public CodeUnitIterator getCodeUnitIterator(String s, Address address, boolean b) {
                    return null;
                }

                @Override
                public CodeUnitIterator getCodeUnitIterator(String s, AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public CodeUnitIterator getCommentCodeUnitIterator(int i, AddressSetView addressSetView) {
                    return null;
                }

                @Override
                public AddressIterator getCommentAddressIterator(int i, AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public AddressIterator getCommentAddressIterator(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public String getComment(int i, Address address) {
                    return null;
                }

                @Override
                public void setComment(Address address, int i, String s) {
                }

                @Override
                public CodeUnitIterator getCodeUnits(boolean b) {
                    return null;
                }

                @Override
                public CodeUnitIterator getCodeUnits(Address address, boolean b) {
                    return null;
                }

                @Override
                public CodeUnitIterator getCodeUnits(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public Instruction getInstructionAt(Address address) {
                    return null;
                }

                @Override
                public Instruction getInstructionContaining(Address address) {
                    return null;
                }

                @Override
                public Instruction getInstructionAfter(Address address) {
                    return null;
                }

                @Override
                public Instruction getInstructionBefore(Address address) {
                    return null;
                }

                @Override
                public InstructionIterator getInstructions(boolean b) {
                    return null;
                }

                @Override
                public InstructionIterator getInstructions(Address address, boolean b) {
                    return null;
                }

                @Override
                public InstructionIterator getInstructions(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public Data getDataAt(Address address) {
                    return null;
                }

                @Override
                public Data getDataContaining(Address address) {
                    return null;
                }

                @Override
                public Data getDataAfter(Address address) {
                    return null;
                }

                @Override
                public Data getDataBefore(Address address) {
                    return null;
                }

                @Override
                public DataIterator getData(boolean b) {
                    return null;
                }

                @Override
                public DataIterator getData(Address address, boolean b) {
                    return null;
                }

                @Override
                public DataIterator getData(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public Data getDefinedDataAt(Address address) {
                    return null;
                }

                @Override
                public Data getDefinedDataContaining(Address address) {
                    return null;
                }

                @Override
                public Data getDefinedDataAfter(Address address) {
                    return null;
                }

                @Override
                public Data getDefinedDataBefore(Address address) {
                    return null;
                }

                @Override
                public DataIterator getDefinedData(boolean b) {
                    return null;
                }

                @Override
                public DataIterator getDefinedData(Address address, boolean b) {
                    return null;
                }

                @Override
                public DataIterator getDefinedData(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public Data getUndefinedDataAt(Address address) {
                    return null;
                }

                @Override
                public Data getUndefinedDataAfter(Address address, TaskMonitor taskMonitor) {
                    return null;
                }

                @Override
                public Data getFirstUndefinedData(AddressSetView addressSetView, TaskMonitor taskMonitor) {
                    return null;
                }

                @Override
                public Data getUndefinedDataBefore(Address address, TaskMonitor taskMonitor) {
                    return null;
                }

                @Override
                public AddressSetView getUndefinedRanges(AddressSetView addressSetView, boolean b, TaskMonitor taskMonitor) throws CancelledException {
                    return null;
                }

                @Override
                public CodeUnit getDefinedCodeUnitAfter(Address address) {
                    return null;
                }

                @Override
                public CodeUnit getDefinedCodeUnitBefore(Address address) {
                    return null;
                }

                @Override
                public DataIterator getCompositeData(boolean b) {
                    return null;
                }

                @Override
                public DataIterator getCompositeData(Address address, boolean b) {
                    return null;
                }

                @Override
                public DataIterator getCompositeData(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public Iterator<String> getUserDefinedProperties() {
                    return null;
                }

                @Override
                public void removeUserDefinedProperty(String s) {
                }

                @Override
                public PropertyMap getPropertyMap(String s) {
                    return null;
                }

                @Override
                public Instruction createInstruction(Address address, InstructionPrototype instructionPrototype, MemBuffer memBuffer, ProcessorContextView processorContextView, int i) throws CodeUnitInsertionException {
                    return null;
                }

                @Override
                public AddressSetView addInstructions(InstructionSet instructionSet, boolean b) throws CodeUnitInsertionException {
                    return null;
                }

                @Override
                public Data createData(Address address, DataType dataType, int i) throws CodeUnitInsertionException {
                    return null;
                }

                @Override
                public Data createData(Address address, DataType dataType) throws CodeUnitInsertionException {
                    return null;
                }

                @Override
                public void clearCodeUnits(Address address, Address address1, boolean b) {
                }

                @Override
                public void clearCodeUnits(Address address, Address address1, boolean b, TaskMonitor taskMonitor) throws CancelledException {
                }

                @Override
                public boolean isUndefined(Address address, Address address1) {
                    return false;
                }

                @Override
                public void clearComments(Address address, Address address1) {
                }

                @Override
                public void clearProperties(Address address, Address address1, TaskMonitor taskMonitor) throws CancelledException {
                }

                @Override
                public void clearAll(boolean b, TaskMonitor taskMonitor) {
                }

                @Override
                public ProgramFragment getFragment(String s, Address address) {
                    return null;
                }

                @Override
                public ProgramModule getModule(String s, String s1) {
                    return null;
                }

                @Override
                public ProgramFragment getFragment(String s, String s1) {
                    return null;
                }

                @Override
                public ProgramModule createRootModule(String s) throws DuplicateNameException {
                    return null;
                }

                @Override
                public ProgramModule getRootModule(String s) {
                    return null;
                }

                @Override
                public ProgramModule getRootModule(long l) {
                    return null;
                }

                @Override
                public ProgramModule getDefaultRootModule() {
                    return null;
                }

                @Override
                public String[] getTreeNames() {
                    return new String[0];
                }

                @Override
                public boolean removeTree(String s) {
                    return false;
                }

                @Override
                public void renameTree(String s, String s1) throws DuplicateNameException {
                }

                @Override
                public long getNumCodeUnits() {
                    return 0;
                }

                @Override
                public long getNumDefinedData() {
                    return 0;
                }

                @Override
                public long getNumInstructions() {
                    return 0;
                }

                @Override
                public DataTypeManager getDataTypeManager() {
                    return null;
                }

                @Override
                public Function createFunction(String s, Address address, AddressSetView addressSetView, SourceType sourceType) throws InvalidInputException, OverlappingFunctionException {
                    return null;
                }

                @Override
                public Function createFunction(String s, Namespace namespace, Address address, AddressSetView addressSetView, SourceType sourceType) throws InvalidInputException, OverlappingFunctionException {
                    return null;
                }

                @Override
                public void removeFunction(Address address) {
                }

                @Override
                public Function getFunctionAt(Address address) {
                    return null;
                }

                @Override
                public List<Function> getGlobalFunctions(String s) {
                    return null;
                }

                @Override
                public List<Function> getFunctions(String s, String s1) {
                    return null;
                }

                @Override
                public Function getFunctionContaining(Address address) {
                    return null;
                }

                @Override
                public FunctionIterator getExternalFunctions() {
                    return null;
                }

                @Override
                public FunctionIterator getFunctions(boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctions(Address address, boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctions(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public boolean isInFunction(Address address) {
                    return false;
                }

                @Override
                public CommentHistory[] getCommentHistory(Address address, int i) {
                    return new CommentHistory[0];
                }
            };
        }

        @SuppressWarnings("removal")
        @Override
        public AddressMap getAddressMap() {
            return new AddressMap() {
                @Override
                public long getKey(Address address, boolean b) {
                    return 0;
                }

                @Override
                public long getAbsoluteEncoding(Address address, boolean b) {
                    return 0;
                }

                @Override
                public int findKeyRange(List<KeyRange> list, Address address) {
                    return 0;
                }

                @Override
                public List<KeyRange> getKeyRanges(Address address, Address address1, boolean b) {
                    return null;
                }

                @Override
                public List<KeyRange> getKeyRanges(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public Address decodeAddress(long l) {
                    return null;
                }

                @Override
                public AddressFactory getAddressFactory() {
                    return null;
                }

                @Override
                public List<KeyRange> getKeyRanges(Address address, Address address1, boolean b, boolean b1) {
                    return null;
                }

                @Override
                public List<KeyRange> getKeyRanges(AddressSetView addressSetView, boolean b, boolean b1) {
                    return null;
                }

                @Override
                public AddressMap getOldAddressMap() {
                    return null;
                }

                @Override
                public boolean isUpgraded() {
                    return false;
                }

                @Override
                public Address getImageBase() {
                    return null;
                }
            };
        }

        @Override
        public ProgramBasedDataTypeManager getDataTypeManager() {
            return null;
        }

        @Override
        public FunctionManager getFunctionManager() {
            var program = this;
            return new FunctionManager() {
                @Override
                public Program getProgram() {
                    return program;
                }

                @Override
                public Collection<String> getCallingConventionNames() {
                    return Collections.emptyList();
                }

                @Override
                public PrototypeModel getDefaultCallingConvention() {
                    return null;
                }

                @Override
                public PrototypeModel getCallingConvention(String s) {
                    return null;
                }

                @Override
                public Function createFunction(String s, Address address, AddressSetView addressSetView, SourceType sourceType) throws InvalidInputException, OverlappingFunctionException {
                    return null;
                }

                @Override
                public Function createFunction(String s, Namespace namespace, Address address, AddressSetView addressSetView, SourceType sourceType) throws InvalidInputException, OverlappingFunctionException {
                    return null;
                }

                @Override
                public Function createThunkFunction(String s, Namespace namespace, Address address, AddressSetView addressSetView, Function function, SourceType sourceType) throws OverlappingFunctionException {
                    return null;
                }

                @Override
                public int getFunctionCount() {
                    return 0;
                }

                @Override
                public boolean removeFunction(Address address) {
                    return false;
                }

                @Override
                public Function getFunctionAt(Address address) {
                    return null;
                }

                @Override
                public Function getReferencedFunction(Address address) {
                    return null;
                }

                @Override
                public Function getFunctionContaining(Address address) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctions(boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctions(Address address, boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctions(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctionsNoStubs(boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctionsNoStubs(Address address, boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getFunctionsNoStubs(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public FunctionIterator getExternalFunctions() {
                    return null;
                }

                @Override
                public boolean isInFunction(Address address) {
                    return false;
                }

                @Override
                public Iterator<Function> getFunctionsOverlapping(AddressSetView addressSetView) {
                    return null;
                }

                @Override
                public Variable getReferencedVariable(Address address, Address address1, int i, boolean b) {
                    return null;
                }

                @Override
                public Function getFunction(long l) {
                    return null;
                }

                @Override
                public FunctionTagManager getFunctionTagManager() {
                    return null;
                }

                @Override
                public void invalidateCache(boolean b) {
                }

                @Override
                public void moveAddressRange(Address address, Address address1, long l, TaskMonitor taskMonitor) throws CancelledException {
                }

                @Override
                public void setProgram(ProgramDB programDB) {
                }

                @Override
                public void programReady(int i, int i1, TaskMonitor taskMonitor) throws IOException, CancelledException {
                }

                @Override
                public void deleteAddressRange(Address address, Address address1, TaskMonitor taskMonitor) throws CancelledException {
                }
            };
        }

        @Override
        public ProgramUserData getProgramUserData() {
            return null;
        }

        @Override
        public SymbolTable getSymbolTable() {
            return new SymbolTable() {
                @Override
                public Symbol createLabel(Address address, String s, SourceType sourceType) throws InvalidInputException {
                    return null;
                }

                @Override
                public Symbol createLabel(Address address, String s, Namespace namespace, SourceType sourceType) throws InvalidInputException {
                    return null;
                }

                @Override
                public boolean removeSymbolSpecial(Symbol symbol) {
                    return false;
                }

                @Override
                public Symbol getSymbol(long l) {
                    return null;
                }

                @Override
                public Symbol getSymbol(String s, Address address, Namespace namespace) {
                    return null;
                }

                @Override
                public Symbol getGlobalSymbol(String s, Address address) {
                    return null;
                }

                @Override
                public List<Symbol> getGlobalSymbols(String s) {
                    return Collections.emptyList();
                }

                @Override
                public List<Symbol> getLabelOrFunctionSymbols(String s, Namespace namespace) {
                    return Collections.emptyList();
                }

                @Override
                public Symbol getNamespaceSymbol(String s, Namespace namespace) {
                    return null;
                }

                @Override
                public Symbol getLibrarySymbol(String s) {
                    return null;
                }

                @Override
                public Symbol getClassSymbol(String s, Namespace namespace) {
                    return null;
                }

                @Override
                public Symbol getParameterSymbol(String s, Namespace namespace) {
                    return null;
                }

                @Override
                public Symbol getLocalVariableSymbol(String s, Namespace namespace) {
                    return null;
                }

                @Override
                public List<Symbol> getSymbols(String s, Namespace namespace) {
                    return Collections.emptyList();
                }

                @Override
                public Symbol getVariableSymbol(String s, Function function) {
                    return null;
                }

                @Override
                public Namespace getNamespace(String s, Namespace namespace) {
                    return null;
                }

                @Override
                public SymbolIterator getSymbols(String s) {
                    return null;
                }

                @Override
                public SymbolIterator getAllSymbols(boolean b) {
                    return null;
                }

                @Override
                public Symbol getSymbol(Reference reference) {
                    return null;
                }

                @Override
                public Symbol getPrimarySymbol(Address address) {
                    return null;
                }

                @Override
                public Symbol[] getSymbols(Address address) {
                    return new Symbol[0];
                }

                @Override
                public SymbolIterator getSymbolsAsIterator(Address address) {
                    return null;
                }

                @Override
                public Symbol[] getUserSymbols(Address address) {
                    return new Symbol[0];
                }

                @Override
                public SymbolIterator getSymbols(Namespace namespace) {
                    return null;
                }

                @Override
                public SymbolIterator getSymbols(long l) {
                    return null;
                }

                @Override
                public boolean hasSymbol(Address address) {
                    return false;
                }

                @Override
                public long getDynamicSymbolID(Address address) {
                    return 0;
                }

                @Override
                public SymbolIterator getSymbolIterator(String s, boolean b) {
                    return null;
                }

                @Override
                public SymbolIterator getSymbols(AddressSetView addressSetView, SymbolType symbolType, boolean b) {
                    return null;
                }

                @Override
                public SymbolIterator scanSymbolsByName(String s) {
                    return null;
                }

                @Override
                public int getNumSymbols() {
                    return 0;
                }

                @Override
                public SymbolIterator getSymbolIterator() {
                    return null;
                }

                @Override
                public SymbolIterator getDefinedSymbols() {
                    return null;
                }

                @Override
                public Symbol getExternalSymbol(String s) {
                    return null;
                }

                @Override
                public SymbolIterator getExternalSymbols(String s) {
                    return null;
                }

                @Override
                public SymbolIterator getExternalSymbols() {
                    return null;
                }

                @Override
                public SymbolIterator getSymbolIterator(boolean b) {
                    return null;
                }

                @Override
                public SymbolIterator getSymbolIterator(Address address, boolean b) {
                    return null;
                }

                @Override
                public SymbolIterator getPrimarySymbolIterator(boolean b) {
                    return null;
                }

                @Override
                public SymbolIterator getPrimarySymbolIterator(Address address, boolean b) {
                    return null;
                }

                @Override
                public SymbolIterator getPrimarySymbolIterator(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public void addExternalEntryPoint(Address address) {
                }

                @Override
                public void removeExternalEntryPoint(Address address) {
                }

                @Override
                public boolean isExternalEntryPoint(Address address) {
                    return false;
                }

                @Override
                public AddressIterator getExternalEntryPointIterator() {
                    return null;
                }

                @Override
                public LabelHistory[] getLabelHistory(Address address) {
                    return new LabelHistory[0];
                }

                @Override
                public Iterator<LabelHistory> getLabelHistory() {
                    return null;
                }

                @Override
                public boolean hasLabelHistory(Address address) {
                    return false;
                }

                @Override
                public Namespace getNamespace(Address address) {
                    return null;
                }

                @Override
                public Iterator<GhidraClass> getClassNamespaces() {
                    return null;
                }

                @Override
                public GhidraClass createClass(Namespace namespace, String s, SourceType sourceType) throws DuplicateNameException, InvalidInputException {
                    return null;
                }

                @Override
                public SymbolIterator getChildren(Symbol symbol) {
                    return null;
                }

                @Override
                public Library createExternalLibrary(String s, SourceType sourceType) throws DuplicateNameException, InvalidInputException {
                    return null;
                }

                @Override
                public Namespace createNameSpace(Namespace namespace, String s, SourceType sourceType) throws DuplicateNameException, InvalidInputException {
                    return null;
                }

                @Override
                public GhidraClass convertNamespaceToClass(Namespace namespace) {
                    return null;
                }

                @Override
                public Namespace getOrCreateNameSpace(Namespace namespace, String s, SourceType sourceType) throws DuplicateNameException, InvalidInputException {
                    return null;
                }
            };
        }

        @Override
        public ExternalManager getExternalManager() {
            return null;
        }

        @Override
        public EquateTable getEquateTable() {
            return null;
        }

        @Override
        public Memory getMemory() {
            var program = this;
            return new Memory() {
                @Override
                public Program getProgram() {
                    return program;
                }

                @Override
                public AddressSetView getLoadedAndInitializedAddressSet() {
                    return null;
                }

                @Override
                public AddressSetView getAllInitializedAddressSet() {
                    return null;
                }

                @Override
                public AddressSetView getInitializedAddressSet() {
                    return null;
                }

                @Override
                public AddressSetView getExecuteSet() {
                    return null;
                }

                @Override
                public boolean isBigEndian() {
                    return false;
                }

                @Override
                public void setLiveMemoryHandler(LiveMemoryHandler liveMemoryHandler) {
                }

                @Override
                public LiveMemoryHandler getLiveMemoryHandler() {
                    return null;
                }

                @Override
                public MemoryBlock createInitializedBlock(String s, Address address, InputStream inputStream, long l, TaskMonitor taskMonitor, boolean b) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, IllegalArgumentException {
                    return null;
                }

                @Override
                public MemoryBlock createInitializedBlock(String s, Address address, long l, byte b, TaskMonitor taskMonitor, boolean b1) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, CancelledException {
                    return null;
                }

                @Override
                public MemoryBlock createInitializedBlock(String s, Address address, FileBytes fileBytes, long l, long l1, boolean b) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException {
                    return null;
                }

                @Override
                public MemoryBlock createUninitializedBlock(String s, Address address, long l, boolean b) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException {
                    return null;
                }

                @Override
                public MemoryBlock createBitMappedBlock(String s, Address address, Address address1, long l, boolean b) throws LockException, MemoryConflictException, AddressOverflowException, IllegalArgumentException {
                    return null;
                }

                @Override
                public MemoryBlock createByteMappedBlock(String s, Address address, Address address1, long l, ByteMappingScheme byteMappingScheme, boolean b) throws LockException, MemoryConflictException, AddressOverflowException, IllegalArgumentException {
                    return null;
                }

                @Override
                public MemoryBlock createBlock(MemoryBlock memoryBlock, String s, Address address, long l) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException {
                    return null;
                }

                @Override
                public void removeBlock(MemoryBlock memoryBlock, TaskMonitor taskMonitor) throws LockException {
                }

                @Override
                public long getSize() {
                    return 0;
                }

                @Override
                public MemoryBlock getBlock(Address address) {
                    return null;
                }

                @Override
                public MemoryBlock getBlock(String s) {
                    return null;
                }

                @Override
                public MemoryBlock[] getBlocks() {
                    return new MemoryBlock[0];
                }

                @Override
                public void moveBlock(MemoryBlock memoryBlock, Address address, TaskMonitor taskMonitor) throws LockException, MemoryBlockException, MemoryConflictException, AddressOverflowException, NotFoundException {
                }

                @Override
                public void split(MemoryBlock memoryBlock, Address address) throws MemoryBlockException, LockException, NotFoundException {
                }

                @Override
                public MemoryBlock join(MemoryBlock memoryBlock, MemoryBlock memoryBlock1) throws LockException, MemoryBlockException, NotFoundException {
                    return null;
                }

                @Override
                public MemoryBlock convertToInitialized(MemoryBlock memoryBlock, byte b) throws LockException, MemoryBlockException, NotFoundException {
                    return null;
                }

                @Override
                public MemoryBlock convertToUninitialized(MemoryBlock memoryBlock) throws MemoryBlockException, NotFoundException, LockException {
                    return null;
                }

                @Override
                public Address findBytes(Address address, byte[] bytes, byte[] bytes1, boolean b, TaskMonitor taskMonitor) {
                    return null;
                }

                @Override
                public Address findBytes(Address address, Address address1, byte[] bytes, byte[] bytes1, boolean b, TaskMonitor taskMonitor) {
                    return null;
                }

                @Override
                public byte getByte(Address address) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getBytes(Address address, byte[] bytes) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getBytes(Address address, byte[] bytes, int i, int i1) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public short getShort(Address address) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public short getShort(Address address, boolean b) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getShorts(Address address, short[] shorts) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getShorts(Address address, short[] shorts, int i, int i1) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getShorts(Address address, short[] shorts, int i, int i1, boolean b) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getInt(Address address) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getInt(Address address, boolean b) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getInts(Address address, int[] ints) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getInts(Address address, int[] ints, int i, int i1) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getInts(Address address, int[] ints, int i, int i1, boolean b) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public long getLong(Address address) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public long getLong(Address address, boolean b) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getLongs(Address address, long[] longs) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getLongs(Address address, long[] longs, int i, int i1) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public int getLongs(Address address, long[] longs, int i, int i1, boolean b) throws MemoryAccessException {
                    return 0;
                }

                @Override
                public void setByte(Address address, byte b) throws MemoryAccessException {
                }

                @Override
                public void setBytes(Address address, byte[] bytes) throws MemoryAccessException {
                }

                @Override
                public void setBytes(Address address, byte[] bytes, int i, int i1) throws MemoryAccessException {
                }

                @Override
                public void setShort(Address address, short i) throws MemoryAccessException {
                }

                @Override
                public void setShort(Address address, short i, boolean b) throws MemoryAccessException {
                }

                @Override
                public void setInt(Address address, int i) throws MemoryAccessException {
                }

                @Override
                public void setInt(Address address, int i, boolean b) throws MemoryAccessException {
                }

                @Override
                public void setLong(Address address, long l) throws MemoryAccessException {
                }

                @Override
                public void setLong(Address address, long l, boolean b) throws MemoryAccessException {
                }

                @Override
                public FileBytes createFileBytes(String s, long l, long l1, InputStream inputStream, TaskMonitor taskMonitor) throws IOException, CancelledException {
                    return null;
                }

                @Override
                public List<FileBytes> getAllFileBytes() {
                    return null;
                }

                @Override
                public boolean deleteFileBytes(FileBytes fileBytes) throws IOException {
                    return false;
                }

                @Override
                public AddressSourceInfo getAddressSourceInfo(Address address) {
                    return null;
                }

                @Override
                public boolean contains(Address address) {
                    return false;
                }

                @Override
                public boolean contains(Address address, Address address1) {
                    return false;
                }

                @Override
                public boolean contains(AddressSetView addressSetView) {
                    return false;
                }

                @Override
                public boolean isEmpty() {
                    return false;
                }

                @Override
                public Address getMinAddress() {
                    return null;
                }

                @Override
                public Address getMaxAddress() {
                    return null;
                }

                @Override
                public int getNumAddressRanges() {
                    return 0;
                }

                @Override
                public AddressRangeIterator getAddressRanges() {
                    return null;
                }

                @Override
                public AddressRangeIterator getAddressRanges(boolean b) {
                    return null;
                }

                @Override
                public AddressRangeIterator getAddressRanges(Address address, boolean b) {
                    return null;
                }

                @Override
                public Iterator<AddressRange> iterator() {
                    return null;
                }

                @Override
                public Iterator<AddressRange> iterator(boolean b) {
                    return null;
                }

                @Override
                public Iterator<AddressRange> iterator(Address address, boolean b) {
                    return null;
                }

                @Override
                public long getNumAddresses() {
                    return 0;
                }

                @Override
                public AddressIterator getAddresses(boolean b) {
                    return null;
                }

                @Override
                public AddressIterator getAddresses(Address address, boolean b) {
                    return null;
                }

                @Override
                public boolean intersects(AddressSetView addressSetView) {
                    return false;
                }

                @Override
                public boolean intersects(Address address, Address address1) {
                    return false;
                }

                @Override
                public AddressSet intersect(AddressSetView addressSetView) {
                    return null;
                }

                @Override
                public AddressSet intersectRange(Address address, Address address1) {
                    return null;
                }

                @Override
                public AddressSet union(AddressSetView addressSetView) {
                    return null;
                }

                @Override
                public AddressSet subtract(AddressSetView addressSetView) {
                    return null;
                }

                @Override
                public AddressSet xor(AddressSetView addressSetView) {
                    return null;
                }

                @Override
                public boolean hasSameAddresses(AddressSetView addressSetView) {
                    return false;
                }

                @Override
                public AddressRange getFirstRange() {
                    return null;
                }

                @Override
                public AddressRange getLastRange() {
                    return null;
                }

                @Override
                public AddressRange getRangeContaining(Address address) {
                    return null;
                }

                @Override
                public Address findFirstAddressInCommon(AddressSetView addressSetView) {
                    return null;
                }
            };
        }

        @Override
        public ReferenceManager getReferenceManager() {
            return new ReferenceManager() {
                @Override
                public Reference addReference(Reference reference) {
                    return null;
                }

                @Override
                public Reference addStackReference(Address address, int i, int i1, RefType refType, SourceType sourceType) {
                    return null;
                }

                @Override
                public Reference addRegisterReference(Address address, int i, Register register, RefType refType, SourceType sourceType) {
                    return null;
                }

                @Override
                public Reference addMemoryReference(Address address, Address address1, RefType refType, SourceType sourceType, int i) {
                    return null;
                }

                @Override
                public Reference addOffsetMemReference(Address address, Address address1, boolean b, long l, RefType refType, SourceType sourceType, int i) {
                    return null;
                }

                @Override
                public Reference addShiftedMemReference(Address address, Address address1, int i, RefType refType, SourceType sourceType, int i1) {
                    return null;
                }

                @Override
                public Reference addExternalReference(Address address, String s, String s1, Address address1, SourceType sourceType, int i, RefType refType) throws InvalidInputException, DuplicateNameException {
                    return null;
                }

                @Override
                public Reference addExternalReference(Address address, Namespace namespace, String s, Address address1, SourceType sourceType, int i, RefType refType) throws InvalidInputException, DuplicateNameException {
                    return null;
                }

                @Override
                public Reference addExternalReference(Address address, int i, ExternalLocation externalLocation, SourceType sourceType, RefType refType) throws InvalidInputException {
                    return null;
                }

                @Override
                public void removeAllReferencesFrom(Address address, Address address1) {
                }

                @Override
                public void removeAllReferencesFrom(Address address) {
                }

                @Override
                public void removeAllReferencesTo(Address address) {
                }

                @Override
                public Reference[] getReferencesTo(Variable variable) {
                    return new Reference[0];
                }

                @Override
                public Variable getReferencedVariable(Reference reference) {
                    return null;
                }

                @Override
                public void setPrimary(Reference reference, boolean b) {
                }

                @Override
                public boolean hasFlowReferencesFrom(Address address) {
                    return false;
                }

                @Override
                public Reference[] getFlowReferencesFrom(Address address) {
                    return new Reference[0];
                }

                @Override
                public ReferenceIterator getExternalReferences() {
                    return null;
                }

                @Override
                public ReferenceIterator getReferencesTo(Address address) {
                    return null;
                }

                @Override
                public ReferenceIterator getReferenceIterator(Address address) {
                    return null;
                }

                @Override
                public Reference getReference(Address address, Address address1, int i) {
                    return null;
                }

                @Override
                public Reference[] getReferencesFrom(Address address) {
                    return new Reference[0];
                }

                @Override
                public Reference[] getReferencesFrom(Address address, int i) {
                    return new Reference[0];
                }

                @Override
                public boolean hasReferencesFrom(Address address, int i) {
                    return false;
                }

                @Override
                public boolean hasReferencesFrom(Address address) {
                    return false;
                }

                @Override
                public Reference getPrimaryReferenceFrom(Address address, int i) {
                    return null;
                }

                @Override
                public AddressIterator getReferenceSourceIterator(Address address, boolean b) {
                    return null;
                }

                @Override
                public AddressIterator getReferenceSourceIterator(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public AddressIterator getReferenceDestinationIterator(Address address, boolean b) {
                    return null;
                }

                @Override
                public AddressIterator getReferenceDestinationIterator(AddressSetView addressSetView, boolean b) {
                    return null;
                }

                @Override
                public int getReferenceCountTo(Address address) {
                    return 0;
                }

                @Override
                public int getReferenceCountFrom(Address address) {
                    return 0;
                }

                @Override
                public int getReferenceDestinationCount() {
                    return 0;
                }

                @Override
                public int getReferenceSourceCount() {
                    return 0;
                }

                @Override
                public boolean hasReferencesTo(Address address) {
                    return false;
                }

                @Override
                public Reference updateRefType(Reference reference, RefType refType) {
                    return null;
                }

                @Override
                public void setAssociation(Symbol symbol, Reference reference) {
                }

                @Override
                public void removeAssociation(Reference reference) {
                }

                @Override
                public void delete(Reference reference) {
                }

                @Override
                public byte getReferenceLevel(Address address) {
                    return 0;
                }
            };
        }
        @Override
        public BookmarkManager getBookmarkManager() {
            return null;
        }

        @Override
        public int getDefaultPointerSize() {
            return 0;
        }

        @Override
        public String getCompiler() {
            return null;
        }

        @Override
        public void setCompiler(String s) {
        }

        @Override
        public CategoryPath getPreferredRootNamespaceCategoryPath() {
            return null;
        }

        @Override
        public void setPreferredRootNamespaceCategoryPath(String s) {
        }

        @Override
        public String getExecutablePath() {
            return null;
        }

        @Override
        public void setExecutablePath(String s) {
        }

        @Override
        public String getExecutableFormat() {
            return null;
        }

        @Override
        public void setExecutableFormat(String s) {
        }

        @Override
        public String getExecutableMD5() {
            return null;
        }

        @Override
        public void setExecutableMD5(String s) {
        }

        @Override
        public void setExecutableSHA256(String s) {
        }

        @Override
        public String getExecutableSHA256() {
            return null;
        }

        @Override
        public Date getCreationDate() {
            return null;
        }

        @Override
        public RelocationTable getRelocationTable() {
            return null;
        }

        @Override
        public Language getLanguage() {
            return null;
        }

        @Override
        public CompilerSpec getCompilerSpec() {
            return null;
        }

        @Override
        public LanguageID getLanguageID() {
            return null;
        }

        @Override
        public PropertyMapManager getUsrPropertyManager() {
            return null;
        }

        @Override
        public ProgramContext getProgramContext() {
            return null;
        }

        @Override
        public Address getMinAddress() {
            return null;
        }

        @Override
        public Address getMaxAddress() {
            return null;
        }

        @Override
        public ProgramChangeSet getChanges() {
            return null;
        }

        @Override
        public AddressFactory getAddressFactory() {
            return null;
        }

        @Override
        public Address[] parseAddress(String s) {
            return new Address[0];
        }

        @Override
        public Address[] parseAddress(String s, boolean b) {
            return new Address[0];
        }

        @Override
        public void invalidate() {
        }

        @Override
        public ProgramOverlayAddressSpace createOverlaySpace(String s, AddressSpace addressSpace) throws IllegalStateException, DuplicateNameException, InvalidNameException, LockException {
            return null;
        }

        @Override
        public void renameOverlaySpace(String s, String s1) throws NotFoundException, InvalidNameException, DuplicateNameException, LockException {
        }

        @Override
        public boolean removeOverlaySpace(String s) throws LockException, NotFoundException {
            return false;
        }

        @Override
        public Register getRegister(String s) {
            return null;
        }

        @Override
        public Register getRegister(Address address) {
            return null;
        }

        @Override
        public Register[] getRegisters(Address address) {
            return new Register[0];
        }

        @Override
        public Register getRegister(Address address, int i) {
            return null;
        }

        @Override
        public Register getRegister(Varnode varnode) {
            return null;
        }

        @Override
        public Address getImageBase() {
            return null;
        }

        @Override
        public void setImageBase(Address address, boolean b) throws AddressOverflowException, LockException, IllegalStateException {
        }

        @Override
        public void restoreImageBase() {
        }

        @Override
        public void setLanguage(Language language, CompilerSpecID compilerSpecID, boolean b, TaskMonitor taskMonitor) throws IllegalStateException, IncompatibleLanguageException, LockException {
        }

        @Override
        public Namespace getGlobalNamespace() {
            return null;
        }

        @Override
        public AddressSetPropertyMap createAddressSetPropertyMap(String s) throws DuplicateNameException {
            return null;
        }

        @Override
        public IntRangeMap createIntRangeMap(String s) throws DuplicateNameException {
            return null;
        }

        @Override
        public AddressSetPropertyMap getAddressSetPropertyMap(String s) {
            return null;
        }

        @Override
        public IntRangeMap getIntRangeMap(String s) {
            return null;
        }

        @Override
        public void deleteAddressSetPropertyMap(String s) {
        }

        @Override
        public void deleteIntRangeMap(String s) {
        }

        @Override
        public long getUniqueProgramID() {
            return 0;
        }

        @Override
        public Transaction openTransaction(String s) throws IllegalStateException {
            return null;
        }

        @Override
        public int startTransaction(String s) {
            return 0;
        }

        @Override
        public int startTransaction(String s, AbortedTransactionListener abortedTransactionListener) {
            return 0;
        }

        @Override
        public void endTransaction(int i, boolean b) {
        }

        @Override
        public TransactionInfo getCurrentTransactionInfo() {
            return null;
        }

        @Override
        public boolean hasTerminatedTransaction() {
            return false;
        }

        @Override
        public DomainObject[] getSynchronizedDomainObjects() {
            return new DomainObject[0];
        }

        @Override
        public void addSynchronizedDomainObject(DomainObject domainObject) throws LockException {
        }

        @Override
        public void releaseSynchronizedDomainObject() throws LockException {
        }

        @Override
        public boolean isChanged() {
            return false;
        }

        @Override
        public void setTemporary(boolean b) {
        }

        @Override
        public boolean isTemporary() {
            return false;
        }

        @Override
        public boolean isChangeable() {
            return false;
        }

        @Override
        public boolean canSave() {
            return false;
        }

        @Override
        public void save(String s, TaskMonitor taskMonitor) throws IOException, CancelledException {
        }

        @Override
        public void saveToPackedFile(File file, TaskMonitor taskMonitor) throws IOException, CancelledException {
        }

        @Override
        public void release(Object o) {
        }

        @Override
        public void addListener(DomainObjectListener domainObjectListener) {
        }

        @Override
        public void removeListener(DomainObjectListener domainObjectListener) {
        }

        @Override
        public void addCloseListener(DomainObjectClosedListener domainObjectClosedListener) {
        }

        @Override
        public void removeCloseListener(DomainObjectClosedListener domainObjectClosedListener) {
        }

        @Override
        public void addDomainFileListener(DomainObjectFileListener domainObjectFileListener) {
        }

        @Override
        public void removeDomainFileListener(DomainObjectFileListener domainObjectFileListener) {
        }

        @Override
        public EventQueueID createPrivateEventQueue(DomainObjectListener domainObjectListener, int i) {
            return null;
        }

        @Override
        public boolean removePrivateEventQueue(EventQueueID eventQueueID) {
            return false;
        }

        @Override
        public String getDescription() {
            return null;
        }

        @Override
        public String getName() {
            return null;
        }

        @Override
        public void setName(String s) {
        }

        @Override
        public DomainFile getDomainFile() {
            return null;
        }

        @Override
        public boolean addConsumer(Object o) {
            return false;
        }

        @Override
        public List<Object> getConsumerList() {
            return null;
        }

        @Override
        public boolean isUsedBy(Object o) {
            return false;
        }

        @Override
        public void setEventsEnabled(boolean b) {
        }

        @Override
        public boolean isSendingEvents() {
            return false;
        }

        @Override
        public void flushEvents() {
        }

        @Override
        public void flushPrivateEventQueue(EventQueueID eventQueueID) {
        }

        @Override
        public boolean canLock() {
            return false;
        }

        @Override
        public boolean isLocked() {
            return false;
        }

        @Override
        public boolean lock(String s) {
            return false;
        }

        @Override
        public void forceLock(boolean b, String s) {
        }

        @Override
        public void unlock() {
        }

        @Override
        public List<String> getOptionsNames() {
            return null;
        }

        @Override
        public Options getOptions(String s) {
            return null;
        }

        @Override
        public boolean isClosed() {
            return false;
        }

        @Override
        public boolean hasExclusiveAccess() {
            return false;
        }

        @Override
        public Map<String, String> getMetadata() {
            return null;
        }

        @Override
        public long getModificationNumber() {
            return 0;
        }

        @Override
        public boolean canUndo() {
            return false;
        }

        @Override
        public boolean canRedo() {
            return false;
        }

        @Override
        public void clearUndo() {
        }

        @Override
        public void undo() throws IOException {
        }

        @Override
        public void redo() throws IOException {
        }

        @Override
        public String getUndoName() {
            return null;
        }

        @Override
        public String getRedoName() {
            return null;
        }

        @Override
        public List<String> getAllUndoNames() {
            return null;
        }

        @Override
        public List<String> getAllRedoNames() {
            return null;
        }

        @Override
        public void addTransactionListener(TransactionListener transactionListener) {
        }

        @Override
        public void removeTransactionListener(TransactionListener transactionListener) {
        }
    }


    /**
     * This class represents a row in the table
     * It also stores a reference to the [Bundle,Class] pair that will be used to invoke the script
     */
    private static class ScriptRowObject implements AddressableRowObject {
        private final Bundle bundle;
        private final Class scriptClass;

        public ScriptRowObject(Bundle bundle, Class scriptClass){
            this.bundle = bundle;
            this.scriptClass = scriptClass;
        }

        @Override
        public Address getAddress() {
            return Address.NO_ADDRESS;
        }
    }

    /** this is required to avoid the OSGI scanner parsing Class.forName constants and emitting duplicate imports */
    private static Class getClassFromParts(String... parts) throws Exception {
        return Class.forName(String.join(".", parts));
    }

    /**
     * scans for Ghidra scripts in the default scripts package in the given bundle
     * @param bundle    the bundle to search in
     * @return          a collection of [Bundle, Class] pairs for each detected GhidraScript
     */
    private Stream<? extends Pair<Bundle, Class<?>>> collectClasses(Bundle bundle){
        var wiring = bundle.adapt(BundleWiring.class);
        return wiring.listResources("/", "*.class", BundleWiring.FINDENTRIES_RECURSE)
                .stream().filter(path -> bundle.getEntry(path) != null)
                .map(path -> {
                    // remove .class and convert to class name
                    return path.replace('/', '.').substring(0, path.length() - 6);
                })
                .map(it -> {
                    println("path: " + it);
                    try {
                        return new Pair<Bundle, Class<?>>(bundle, bundle.loadClass(it));
                    } catch (ClassNotFoundException|NoClassDefFoundError e) {
                        e.printStackTrace();
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .filter(p -> {
                    println("class: " + p.second.getName());
                    return GhidraScript.class.isAssignableFrom(p.second);
                });
    }

    /**
     * This function constructs a table dialogue with [Bundle] and [Script] columns
     * @param dlg
     */
    private void configureTableColumns(TableChooserDialog dlg){
        var bundleName = new StringColumnDisplay(){
            @Override
            public String getColumnValue(AddressableRowObject addressableRowObject) {
                var row = (ScriptRowObject)addressableRowObject;
                return row.bundle.getSymbolicName();
            }

            @Override
            public String getColumnName() {
                return "Bundle";
            }
        };

        var scriptName = new StringColumnDisplay(){
            @Override
            public String getColumnValue(AddressableRowObject addressableRowObject) {
                var row = (ScriptRowObject)addressableRowObject;
                return row.scriptClass.getName();
            }

            @Override
            public String getColumnName() {
                return "Script";
            }
        };

        dlg.addCustomColumn(bundleName);
        dlg.addCustomColumn(scriptName);
    }

    public void run() throws Exception {
        var thisScript = this;

        var executor = new TableChooserExecutor() {
            @Override
            public String getButtonName() {
                return "Run";
            }

            /**
             * this function is invoked when the user selects a script to run
             * @param addressableRowObject  the chosen script
             * @return
             */
            @Override
            public boolean execute(AddressableRowObject addressableRowObject) {
                var row = (ScriptRowObject)addressableRowObject;

                Class scriptClass = null;
                try {
                    scriptClass = row.bundle.loadClass(row.scriptClass.getName());
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }

                GhidraScript script = null;
                if(scriptClass != null) {
                    /**
                     * Retrieve and call the GhidraScript constructor
                     */
                    PrintWriter writer;
                    try {
                        Constructor<GhidraScript> ctor;
                        ctor = scriptClass.getConstructor(GhidraScript.class);
                        script = ctor.newInstance(thisScript);
                    } catch (NoSuchMethodException
                             | InvocationTargetException
                             | InstantiationException
                             | IllegalAccessException e
                    ) {
                        e.printStackTrace();
                        return false;
                    }

                    /**
                     * Execute the script while passing through the current script's environment
                     */
                    try {
                        script.execute(
                                thisScript.getState(),
                                thisScript.getMonitor(),
                                thisScript.writer
                        );
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                if(script == null){
                    thisScript.printerr(String.format("Couldn't find script '%s'", row.scriptClass.getName()));
                    return false;
                }
                return true;
            }
        };

        var program = new DummyProgram();
        var dlg = new TableChooserDialog(state.getTool(), executor, program, "Choose a script", (Navigatable)null, false);
        configureTableColumns(dlg);

        /**
         * When loading plugins, Ghidra generates an OSGI bundle on the fly
         * It scans for any packages required by the script and emits them as imported dependencies in the generated MANIFEST.MF
         * the problem is that, by referencing "ghidra.app.plugin" directly, it gets appended twice and the script will fail to load.
         * this happens because Ghidra always emits "ghidra.app.plugin" as an implicit dependency for every GhidraScript.
         *
         * We can work around this by using Class.forName instead of a package import.
         * However, it looks like the dependency scanner is smart enough to detect imported packages from string constants used in Class.forName
         * that's why we need to fool the scanner by building the class names on the fly.
         *
         * Even if some of these classes are actually public, we need to use them indirectly through reflection
         */
        var cGhidraScriptUtil = getClassFromParts("ghidra", "app", "script", "GhidraScriptUtil");
        var cGhidraBundleHost = getClassFromParts("ghidra", "app", "plugin", "core", "osgi", "BundleHost");
        var cGhidraBundle = getClassFromParts("ghidra", "app", "plugin", "core", "osgi", "GhidraBundle");

        /**
         * Get the Ghidra bundle host and query loaded bundles
         */
        var host = cGhidraScriptUtil.getDeclaredMethod("getBundleHost").invoke(null);
        var bundles = (Collection<Object>) cGhidraBundleHost.getDeclaredMethod("getGhidraBundles").invoke(host);
        var bundleGetter = cGhidraBundle.getDeclaredMethod("getOSGiBundle");

        /**
         * Probe each loaded bundle for available scripts and populate the table dialogue
         */
        bundles.stream().map(b -> {
                    try {
                        return (Bundle)bundleGetter.invoke(b);
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;
                    }
                }).filter(Objects::nonNull)
                .flatMap(this::collectClasses)
                .forEach(p -> {
                    var row = new ScriptRowObject(p.first, p.second);
                    dlg.add(row);
                });

        dlg.show();
    }
}
