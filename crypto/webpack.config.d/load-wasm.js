config.module.rules.push({
    test: /\.wasm$/,
    type: 'asset/resource',
    include: /node_modules/,
});

config.externals = { ...config.externals, module: 'commonjs module' }