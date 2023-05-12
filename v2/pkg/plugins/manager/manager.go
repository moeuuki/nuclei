package manager

import (
	"context"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	operatorsdsl "github.com/projectdiscovery/nuclei/v2/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v2/pkg/plugins/proto"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
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

	HelperFunctionsInfo []PluginIndexHelperFunction
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
	// ListPlugins is a flag to list plugins
	ListPlugins bool
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

	if options.ListPlugins {
		manager.list()
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

// list lists the plugins
func (m *Manager) list() {
	for _, plugin := range m.plugins {
		gologger.Info().Msgf("%s - %s", plugin.Name, plugin.Type.String())

		if len(plugin.HelperFunctionsInfo) > 0 {
			for _, helper := range plugin.HelperFunctionsInfo {
				gologger.Silent().Msgf("    %s - %d %v", helper.Name, helper.NumberOfArgs, helper.Signatures)
			}
		}
	}
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

type initializeContext struct {
	helperFunctions *proto.HelperFunctionPlugin
}

// initializePlugins initializes the plugins
//
// TODO: Only load plugins that are used during template
// execution to save processing overhead
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
