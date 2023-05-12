package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/plugins/proto"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/sys"
)

// PluginsIndex is the index of plugins
type PluginsIndex struct {
	Plugins map[string]PluginIndexItem `json:"plugins"`
}

// PluginIndexItem is an item in the plugin index
type PluginIndexItem struct {
	Name            string                      `json:"name"`
	PluginType      PluginType                  `json:"plugin_type"`
	HelperFunctions []PluginIndexHelperFunction `json:"helper_functions,omitempty"`
}

// PluginIndexHelperFunction is a helper function in the plugin index
type PluginIndexHelperFunction struct {
	Name         string   `json:"name"`
	NumberOfArgs int      `json:"number_of_args"`
	Signatures   []string `json:"signatures"`
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
			indexItem := &PluginIndexItem{
				Name:       pluginName,
				PluginType: pluginType,
			}
			m.populatePluginInfo(pluginType, pluginName, plugin, indexItem, runtime)

			pluginsIndex.Plugins[pluginName] = *indexItem
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
			Name:                plugin,
			Type:                data.PluginType,
			Path:                pluginPath,
			HelperFunctionsInfo: data.HelperFunctions,
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

// populatePluginInfo populates the plugin info from the plugin
func (m *Manager) populatePluginInfo(pluginType PluginType, pluginName string, plugin string, indexItem *PluginIndexItem, runtime proto.WazeroNewRuntime) {
	switch pluginType {
	case PluginTypeHelperFunction:
		info, err := m.getHelperFunctionInfo(&Plugin{Path: plugin}, runtime)
		if err != nil {
			gologger.Warning().Msgf("Could not get info for helper function plugin %s: %s\n", pluginName, err)
			return
		}
		for _, item := range info.Items {
			indexItem.HelperFunctions = append(indexItem.HelperFunctions, PluginIndexHelperFunction{
				Name:         item.GetName(),
				NumberOfArgs: int(item.NumberOfArgs),
				Signatures:   item.Signatures,
			})
		}
	}
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
