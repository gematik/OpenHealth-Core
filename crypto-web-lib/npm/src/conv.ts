import {InterfaceDeclaration, Node, Project, Type, TypeFormatFlags} from "ts-morph";
import * as fs from "fs";
import {Command} from "commander";

const program = new Command();

program
    .version("0.1.0")
    .option("--module-name <moduleName>", "Specify the module name. Must match the package.json name")
    .option("--module-class-name <moduleName>", "Specify the module class name. This will be the generated class and function name")
    .option("--package-path <importPath>", "Specify the Kotlin package path")
    .arguments("<inputFile> <outputFile>")
    .description("Convert Emscripten *.d.ts to Kotlin")
    .action((inputFile: string, outputFile: string) => {
        const moduleName = program.opts().moduleName || "MainModule";
        const moduleClassName = program.opts().moduleClassName || "MainModule";
        const packagePath = program.opts().packagePath;

        const project = new Project({
            compilerOptions: {
                strict: true,
                strictNullChecks: true,
            },
        });
        const sourceFile = project.addSourceFileAtPath(inputFile);

        function mapTsTypeToKotlin(tsType: Type, parentName?: string): string {
            const isNullable = tsType.isNullable();
            const text = tsType.getNonNullableType().getText(undefined, TypeFormatFlags.UseAliasDefinedOutsideCurrentScope)
            let returnType = text;

            if (text === "this") returnType = parentName ?? "Any";
            if (text === "never") returnType = "Unit";
            if (text === "string") returnType = "String";
            if (text === "number") returnType =  "Number";
            if (text === "boolean") returnType =  "Boolean";
            if (text === "any") returnType =  "Any";
            const arrayElementType = tsType.getArrayElementType();
            if (arrayElementType) {
                returnType = `List<${mapTsTypeToKotlin(arrayElementType)}>`;
            }
            return `${returnType}${isNullable ? '?' : ''}`;
        }

        function convertInterface(interfaceDec: InterfaceDeclaration): string {
            const interfaceName = interfaceDec.getName();
            const extendsClause = interfaceDec.getExtends().map(ext => ext.getText()).join(", ");
            const header = extendsClause
                ? `external interface ${interfaceName} : ${extendsClause} {`
                : `external interface ${interfaceName} {`;
            let kotlin = header + "\n";
            let extraFactories = "";

            interfaceDec.getProperties().forEach(prop => {
                const typeNode = prop.getTypeNode();
                if (typeNode && typeNode.getKindName() === "TypeLiteral") {
                    const propName = prop.getName();
                    const factoryName = propName.charAt(0).toUpperCase() + propName.slice(1) + "Factory";
                    kotlin += `    val ${propName}: ${factoryName}\n`;
                    let factoryKotlin = `external interface ${factoryName} {\n`;
                    if (Node.isTypeLiteral(typeNode)) {
                        typeNode.getMembers().forEach(member => {
                            if (Node.isMethodSignature(member)) {
                                const methodName = member.getName();
                                const params = member.getParameters()
                                    .map(param => {
                                        const paramName = param.getName();
                                        const paramType = param.getType();
                                        return `${paramName}: ${mapTsTypeToKotlin(paramType)}`;
                                    })
                                    .join(", ");
                                const returnType = member.getReturnType();
                                factoryKotlin += `    fun ${methodName}(${params}): ${mapTsTypeToKotlin(returnType, factoryName)}\n`;
                            }
                        });
                    }
                    factoryKotlin += "}\n";
                    extraFactories += factoryKotlin + "\n";
                } else {
                    const propName = prop.getName();
                    const tsType = prop.getType();
                    kotlin += `    val ${propName}: ${mapTsTypeToKotlin(tsType)}\n`;
                }
            });

            interfaceDec.getMethods().forEach(method => {
                const methodName = method.getName();
                const params = method.getParameters()
                    .map(param => {
                        const paramName = param.getName();
                        const paramType = param.getType();
                        return `${paramName}: ${mapTsTypeToKotlin(paramType)}`;
                    })
                    .join(", ");
                const returnType = method.getReturnType();
                kotlin += `    fun ${methodName}(${params}): ${mapTsTypeToKotlin(returnType, interfaceName)}\n`;
            });

            kotlin += "}\n\n" + extraFactories;
            return kotlin;
        }

        let kotlinOutput = "";

        kotlinOutput += "@file:Suppress(\"ALL\")\n\n";
        kotlinOutput += "// This file is autogenerated by conv.ts - DO NOT MODIFY\n\n";

        if (packagePath) {
            kotlinOutput += `package ${packagePath}\n\n`;
        }

        kotlinOutput += `import kotlin.js.Promise\n\n`;

        sourceFile.getTypeAliases().forEach(alias => {
            const aliasName = alias.getName();
            if (aliasName === "MainModule") {
                kotlinOutput += `external interface ${moduleClassName} : WasmModule, EmbindModule\n\n`;
            } else {
                kotlinOutput += `typealias ${aliasName} = Any\n\n`;
            }
        });

        sourceFile.getInterfaces().forEach(interfaceDec => {
            kotlinOutput += convertInterface(interfaceDec) + "\n";
        });

        kotlinOutput += `
@JsModule("${moduleName}")
@JsNonModule
external fun ${moduleClassName}Factory(options: Any? = definedExternally): Promise<${moduleClassName}>
`;

        fs.writeFileSync(outputFile, kotlinOutput);
        console.log(`Output written to ${outputFile}`);
    });

program.parse(process.argv);