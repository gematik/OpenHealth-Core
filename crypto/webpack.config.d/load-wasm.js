config.module.rules.push({
    test: /\.wasm$/,
    type: 'asset/resource',
    include: /node_modules/,
});