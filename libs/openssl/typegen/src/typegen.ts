import * as fs from 'fs';
import ts, {isTypeLiteralNode} from 'typescript';

const source = `
INPUT d.ts

interface EmbindModule {
  Int8Vector: {
    new(): Int8Vector;
  };
  Uint8Vector: {
    new(): Uint8Vector;
  };
  CMAC: {
    create(_0: Uint8Vector, _1: EmbindString): CMAC;
  };
}

KOTLIN:

external interface EmbindModule {
  val Int8Vector: object {
    fun new(): Int8Vector
  }
  val Uint8Vector: object {
    fun new(): Uint8Vector
  }
  val CMAC: object {
    fun create(_0: Uint8Vector, _1: EmbindString): CMAC
  }
}
`

function parseDTS(filePath: string): string {
    const sourceFile = ts.createSourceFile(
        filePath,
        source,//fs.readFileSync(filePath, 'utf8'),
        ts.ScriptTarget.Latest,
        true
    );

    const kotlinDefinitions: string[] = [];

    function visit(node: ts.Node): void {
        if (ts.isPropertySignature(node)) {
            const propertyName = node.name.getText(sourceFile);
            if (node.type && ts.isTypeLiteralNode(node.type)) {
                kotlinDefinitions.push(`    var ${propertyName}: `);
                visit(node.type.members[0])
            } else {
                const propertyType = node.type?.getText(sourceFile) || "Any";
                kotlinDefinitions.push(`    var ${propertyName}: ${mapType(propertyType)}`);
            }
        } else if (ts.isConstructorDeclaration(node)) {
            kotlinDefinitions.push(`    var ${propertyName}: ${mapType(propertyType)}`);
        } else if (ts.isMethodSignature(node) || ts.isFunctionDeclaration(node)) {
            const methodName = node.name!.getText(sourceFile);
            const parameters = node.parameters.map(param => {
                const paramName = param.name.getText(sourceFile);
                const paramType = param.type?.getText(sourceFile) || "Any";
                return `${paramName}: ${mapType(paramType)}`;
            }).join(", ");
            const returnType = node.type?.getText(sourceFile) || "Unit";
            kotlinDefinitions.push(`    fun ${methodName}(${parameters}): ${mapType(returnType)}`);
        } else if (ts.isInterfaceDeclaration(node)) {
            const name = node.name.text;

            const exts = node.heritageClauses?.flatMap((clause) => {
                clause.types?.map((type) => {
                    if (ts.isIdentifier(type.expression)) {
                        return type.expression.text
                    } else {
                        throw "Unsupported type";
                    }
                })
            }).join(", ") ?? "";

            kotlinDefinitions.push(`external interface ${name} ${exts == "" ? " " : ": " + exts}{`);
            node.members.forEach(member => {
                visit(member);
            });
            kotlinDefinitions.push('}');
        }
    }

    function mapType(tsType: string): string {
        if (tsType.includes("|")) {
            return "dynamic"; // Union types
        }
        if (tsType === "this") {
            return "self"; // Map `this` to `self` pattern
        }
        switch (tsType) {
            case 'EmbindString':
            case 'string':
                return 'String';
            case 'number':
                return 'Double';
            case 'boolean':
                return 'Boolean';
            case 'void':
                return 'Unit';
            case 'any':
                return 'Any';
            default:
                return tsType;
        }
    }

    ts.forEachChild(sourceFile, visit);

    return kotlinDefinitions.join('\n');
}

const dtsFilePath: string = '/Users/tobias.schwerdtfeger/Dev/gematik/openhealthcard/libs/openssl/ems_wrapper/build/openssl.d.ts';
const kotlinOutput: string = parseDTS(dtsFilePath);
fs.writeFileSync('output.kt', kotlinOutput);
console.log('Kotlin definitions generated in output.kt');


