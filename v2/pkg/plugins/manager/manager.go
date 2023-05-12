package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	operatorsdsl "github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/plugins/proto"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// Manager is a plugin manager for Nuclei WASM Plugin System
type Manager struct {
	// plugins are only loaded once at startup and so is thread safe
	plugins map[string]*Plugin

	cache wazero.CompilationCache
}

// Plugin is a single Plugin for the engine
type Plugin struct {
	// Name is the name of the plugin
	Name string
	// Type is the type of the plugin
	Type PluginType
	// Path is the path to the plugin
	Path string
}

// PluginType is the type of plugin
type PluginType string

const (
	// PluginTypeInvalid is an invalid plugin type
	PluginTypeInvalid PluginType = "invalid"
	// PluginTypeHelperFunction is the helper function plugin type
	PluginTypeHelperFunction PluginType = "helper-function"
)

func (p PluginType) String() string {
	switch p {
	case PluginTypeHelperFunction:
		return "helper-function"
	default:
		return "invalid"
	}
}

// Options contains configuration options for the plugin manager
type Options struct {
	// CustomPluginsDirectory is custom directory to load plugins from
	CustomPluginsDirectory string
}

// New creates a new plugin manager from provided options
func New(options *Options) (*Manager, error) {
	defaultPluginsDirectory := config.DefaultConfig.PluginsDirectory
	cacheDirectory := config.DefaultConfig.PluginsCacheDirectory

	manager := &Manager{
		plugins: make(map[string]*Plugin),
	}
	if err := manager.createPluginsCache(cacheDirectory); err != nil {
		return nil, errors.Wrap(err, "could not create plugins cache")
	}
	config := wazero.NewRuntimeConfig().
		WithCompilationCache(manager.cache)

	newRuntime := proto.WazeroNewRuntime(func(ctx context.Context) (wazero.Runtime, error) {
		runtime := wazero.NewRuntimeWithConfig(ctx, config)
		if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
			return nil, err
		}
		return runtime, nil
	})

	// If directory doesn't exists, create it and download
	// plugins package from upstream repository.
	if _, err := os.Stat(defaultPluginsDirectory); os.IsNotExist(err) {
		err := os.MkdirAll(defaultPluginsDirectory, 0755)
		if err != nil {
			return nil, err
		}
		// TODO: Implement
		//	err = downloadPluginsPackage(defaultPluginsDirectory)
		//	if err != nil {
		//		return nil, err
		//	}
	}

	err := manager.loadFromDirectory(defaultPluginsDirectory, newRuntime)
	if err != nil {
		return nil, errors.Wrap(err, "could not load plugins from default directory")
	}

	if options.CustomPluginsDirectory != "" {
		err := manager.loadFromDirectory(options.CustomPluginsDirectory, newRuntime)
		if err != nil {
			return nil, errors.Wrap(err, "could not load plugins from custom directory")
		}
	}

	// Initialize the modules
	functions, err := proto.NewHelperFunctionPlugin(context.Background(), proto.WazeroRuntime(newRuntime))
	if err != nil {
		return nil, errors.Wrap(err, "could not create helper function plugin")
	}
	ctx := &initializeContext{
		helperFunctions: functions,
	}
	if err := manager.initializePlugins(ctx); err != nil {
		return nil, errors.Wrap(err, "could not initialize plugins")
	}
	// Set the default helper functions
	dslFunctions := dsl.HelperFunctions()
	operatorsdsl.FunctionNames = dsl.GetFunctionNames(dslFunctions)
	operatorsdsl.HelperFunctions = dslFunctions

	if len(manager.plugins) > 0 {
		gologger.Info().Msgf("Loaded %d plugins", len(manager.plugins))
	}
	// TODO: Add refresh from repository so that every 24 hours
	// we can refresh the plugins from the repository.
	//
	// Apart from the refresh, there should also be a way for templates
	// to force load a plugin. This way if the plugin doesn't exists locally
	// it is loaded from over the internet from repository.

	// TODO: Create a simple server to serve the plugins over HTTPs
	// behind cloudflare and allow uploads of artifacts which
	// are then provided to nuclei users.
	return manager, nil
}

// Close closes the plugin manager
func (m *Manager) Close() error {
	err := m.cache.Close(context.Background())
	return err
}

// createPluginsCache creates a new plugins cache from the specified
// directory.
func (m *Manager) createPluginsCache(directory string) error {
	err := os.MkdirAll(directory, 0755)
	if err != nil {
		return err
	}
	compilationCache, err := wazero.NewCompilationCacheWithDir(directory)
	if err != nil {
		return err
	}
	m.cache = compilationCache
	return nil
}

// PluginsIndex is the index of plugins
type PluginsIndex struct {
	Plugins map[string]PluginIndexItem `json:"plugins"`
}

// UnmarshalFromFile unmarshals the plugins index from file
func (p *PluginsIndex) UnmarshalFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(p)
}

// MarshalToFile marshals the plugins index to file
func (p *PluginsIndex) MarshalToFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(p)
}

// PluginIndexItem is an item in the plugin index
type PluginIndexItem struct {
	Name       string     `json:"name"`
	PluginType PluginType `json:"plugin_type"`
}

// loadFromDirectory loads plugins from the specified directory
func (m *Manager) loadFromDirectory(directory string, runtime proto.WazeroNewRuntime) error {
	// Walk the directory and look for wasm files
	// as well as index.json files.
	plugins, index, err := m.gatherPluginsIndexFromDirectory(directory)
	if err != nil {
		return errors.Wrap(err, "could not gather plugins and index")
	}

	// Load the index file
	pluginsIndex := &PluginsIndex{}
	if index != "" {
		if err := pluginsIndex.UnmarshalFromFile(index); err != nil {
			return errors.Wrap(err, "could not unmarshal plugins index")
		}
	}
	if pluginsIndex.Plugins == nil {
		index = filepath.Join(directory, "index.json")
		pluginsIndex.Plugins = make(map[string]PluginIndexItem)
	}

	// Go through all the plugins and correlate index
	// to load them into the manager.
	var modified bool
	for _, plugin := range plugins {
		pluginName := getPluginName(plugin)

		_, ok := pluginsIndex.Plugins[pluginName]
		if !ok {
			modified = true
			// If the plugin is not present in the index, try to identify it
			// and add it to the index.
			pluginType, err := m.identifyPluginType(plugin, runtime)
			if err != nil {
				return errors.Wrap(err, "could not identify plugin type")
			}
			indexItem := PluginIndexItem{
				Name:       pluginName,
				PluginType: pluginType,
			}
			pluginsIndex.Plugins[pluginName] = indexItem
		}
	}

	for plugin, data := range pluginsIndex.Plugins {
		// If the plugin is already loaded, skip it
		if _, ok := m.plugins[plugin]; ok {
			continue
		}
		if data.PluginType == PluginTypeInvalid {
			continue
		}
		// Load the plugin
		pluginPath := filepath.Join(directory, plugin+".wasm")
		m.plugins[plugin] = &Plugin{
			Name: plugin,
			Type: data.PluginType,
			Path: pluginPath,
		}
	}
	// Marshal the index back to file
	if modified {
		if err := pluginsIndex.MarshalToFile(index); err != nil {
			return errors.Wrap(err, "could not marshal plugins index")
		}
	}
	return nil
}

func getPluginName(path string) string {
	return strings.Trim(filepath.Base(path), ".wasm")
}

// gatherPluginsIndexFromDirectory gathers the plugins and index from the specified directory
func (m *Manager) gatherPluginsIndexFromDirectory(directory string) ([]string, string, error) {
	var plugins []string
	var index string

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		fileName := filepath.Base(path)
		if filepath.Ext(fileName) == ".wasm" {
			plugins = append(plugins, path)
		}
		if fileName == "index.json" && index == "" {
			index = path
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return plugins, index, nil
}

// identifyPluginType identifies the type of plugin from the provided path
func (m *Manager) identifyPluginType(pluginPath string, newRuntime proto.WazeroNewRuntime) (PluginType, error) {
	ctx := context.Background()

	b, err := os.ReadFile(pluginPath)
	if err != nil {
		return PluginTypeInvalid, err
	}
	r, err := newRuntime(ctx)
	if err != nil {
		return PluginTypeInvalid, err
	}

	code, err := r.CompileModule(ctx, b)
	if err != nil {
		return PluginTypeInvalid, err
	}

	module, err := r.InstantiateModule(ctx, code, wazero.NewModuleConfig())
	if err != nil {
		if exitErr, ok := err.(*sys.ExitError); ok && exitErr.ExitCode() != 0 {
			return PluginTypeInvalid, fmt.Errorf("unexpected exit_code: %d", exitErr.ExitCode())
		} else if !ok {
			return PluginTypeInvalid, err
		}
	}
	defer module.Close(ctx)

	info := module.ExportedFunction("helper_function_info")
	execute := module.ExportedFunction("helper_function_execute")

	if info != nil && execute != nil {
		return PluginTypeHelperFunction, nil
	}
	return PluginTypeInvalid, nil
}

type initializeContext struct {
	helperFunctions *proto.HelperFunctionPlugin
}

// initializePlugins initializes the plugins
func (m *Manager) initializePlugins(ctx *initializeContext) error {
	for _, plugin := range m.plugins {
		if err := m.initializePlugin(plugin, ctx); err != nil {
			return errors.Wrap(err, "could not initialize plugin")
		}
	}
	return nil
}

// initializePlugin initializes a single plugin
func (m *Manager) initializePlugin(plugin *Plugin, ctx *initializeContext) error {
	switch plugin.Type {
	case PluginTypeHelperFunction:
		return m.initializeHelperFunctionPlugin(plugin, ctx)
	}
	return nil
}

// initializeHelperFunctionPlugin initializes a helper function plugin
func (m *Manager) initializeHelperFunctionPlugin(plugin *Plugin, ctx *initializeContext) error {
	helper, err := ctx.helperFunctions.Load(context.Background(), plugin.Path)
	if err != nil {
		return errors.Errorf("could not load helper function plugin %s: %s", plugin.Name, err)
	}
	defer helper.Close(context.Background())

	info, err := helper.Info(context.Background(), &proto.Empty{})
	if err != nil {
		return errors.Errorf("could not get info for helper function plugin %s: %s", plugin.Name, err)
	}

	for _, item := range info.Items {
		item := item

		gologger.Verbose().Msgf("Loaded helper function %s with %d arguments", item.GetName(), item.NumberOfArgs)
		dsl.MustAddFunction(dsl.NewWithPositionalArgs(
			item.GetName(),
			int(item.NumberOfArgs),
			makeHelperFunctionPluginExecute(ctx.helperFunctions, plugin.Path, item.GetName()),
		))
	}

	gologger.Verbose().Msgf("Loaded helper function plugin %s", plugin.Name)
	return nil
}

// makeHelperFunctionPluginExecute creates a helper function plugin execute function
func makeHelperFunctionPluginExecute(p *proto.HelperFunctionPlugin, path, function string) func(arguments ...interface{}) (interface{}, error) {
	return func(arguments ...interface{}) (interface{}, error) {
		newPlugin, err := p.Load(context.Background(), path)
		if err != nil {
			return nil, errors.Wrap(err, "could not load plugin")
		}
		defer newPlugin.Close(context.Background())

		resp, err := newPlugin.Execute(context.Background(), &proto.HelperFunctionRequest{
			Args: proto.ToAnyScalarArray(arguments),
			Name: function,
		})
		if err != nil {
			return nil, errors.Wrap(err, "could not execute plugin")
		}
		return proto.ToAnyScalarValue(resp.Result), nil
	}
}
